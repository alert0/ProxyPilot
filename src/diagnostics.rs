use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    net::IpAddr,
    process::{Command, Stdio},
    str::FromStr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressTestResult {
    pub port: u16,
    pub egress_ip: Option<IpAddr>,
    pub elapsed_ms: u128,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsPathTestResult {
    pub port: u16,
    pub http_status: Option<u16>,
    pub elapsed_ms: u128,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticRecord {
    pub checked_at_unix: u64,
    pub kind: String,
    pub port: u16,
    pub success: bool,
    pub egress_ip: Option<String>,
    pub http_status: Option<u16>,
    pub elapsed_ms: u128,
    pub message: String,
}

impl From<EgressTestResult> for DiagnosticRecord {
    fn from(result: EgressTestResult) -> Self {
        Self {
            checked_at_unix: now_unix(),
            kind: "egress_ip".to_owned(),
            port: result.port,
            success: result.egress_ip.is_some(),
            egress_ip: result.egress_ip.map(|ip| ip.to_string()),
            http_status: None,
            elapsed_ms: result.elapsed_ms,
            message: result.message,
        }
    }
}

impl From<DnsPathTestResult> for DiagnosticRecord {
    fn from(result: DnsPathTestResult) -> Self {
        Self {
            checked_at_unix: now_unix(),
            kind: "remote_dns_path".to_owned(),
            port: result.port,
            success: result.http_status.is_some_and(|status| (200..=399).contains(&status)),
            egress_ip: None,
            http_status: result.http_status,
            elapsed_ms: result.elapsed_ms,
            message: result.message,
        }
    }
}

/// Append sanitized diagnostic results to a bounded local history. No URLs,
/// credentials, or raw curl output are persisted.
pub fn append_history(records: &[DiagnosticRecord]) -> Result<(), String> {
    let dirs = ProjectDirs::from("com", "alert0", "ProxyPilot")
        .ok_or_else(|| "无法确定本地诊断历史目录".to_owned())?;
    save_history_to(&dirs.config_dir().join("diagnostics.json"), records)
}

fn save_history_to(path: &std::path::Path, records: &[DiagnosticRecord]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "诊断历史路径无效".to_owned())?;
    fs::create_dir_all(parent).map_err(|_| "无法创建诊断历史目录".to_owned())?;
    let mut history: Vec<DiagnosticRecord> = if path.exists() {
        let raw = fs::read_to_string(path).map_err(|_| "无法读取现有诊断历史".to_owned())?;
        serde_json::from_str(&raw).map_err(|_| "诊断历史格式无效；原文件已保留".to_owned())?
    } else {
        Vec::new()
    };
    history.extend_from_slice(records);
    history.sort_by_key(|record| record.checked_at_unix);
    if history.len() > 500 {
        let excess = history.len() - 500;
        history.drain(..excess);
    }
    let json = serde_json::to_vec_pretty(&history)
        .map_err(|_| "无法序列化诊断历史".to_owned())?;
    let temporary = path.with_extension("json.tmp");
    {
        let mut file = fs::File::create(&temporary)
            .map_err(|_| "无法创建诊断历史临时文件".to_owned())?;
        file.write_all(&json)
            .map_err(|_| "无法写入诊断历史".to_owned())?;
        file.sync_all()
            .map_err(|_| "无法刷新诊断历史".to_owned())?;
    }
    fs::rename(&temporary, path).map_err(|_| "无法替换诊断历史文件".to_owned())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Checks egress using curl's SOCKS5 hostname mode. The hostname is sent through
/// the proxy; this verifies this request path only and is not a browser-wide leak test.
pub fn test_egress_ip(port: u16) -> EgressTestResult {
    let started = Instant::now();
    let proxy = format!("127.0.0.1:{port}");
    let output = Command::new("curl.exe")
        .args([
            "--connect-timeout",
            "5",
            "--max-time",
            "12",
            "--silent",
            "--show-error",
            "--fail",
            "--socks5-hostname",
            proxy.as_str(),
            "https://api.ipify.org",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let elapsed_ms = started.elapsed().as_millis();
    match output {
        Err(_) => EgressTestResult {
            port,
            egress_ip: None,
            elapsed_ms,
            message: "无法运行 curl.exe；请确认 Windows curl 可用".to_owned(),
        },
        Ok(output) if !output.status.success() => EgressTestResult {
            port,
            egress_ip: None,
            elapsed_ms,
            message: format!(
                "请求失败（curl 退出码 {:?}）；请检查端口监听、节点和网络",
                output.status.code()
            ),
        },
        Ok(output) => match parse_ip_response(&output.stdout) {
            Some(ip) => EgressTestResult {
                port,
                egress_ip: Some(ip),
                elapsed_ms,
                message: "出口 IP 查询成功（SOCKS5 远程解析请求路径）".to_owned(),
            },
            None => EgressTestResult {
                port,
                egress_ip: None,
                elapsed_ms,
                message: "测试服务返回内容不是有效 IP；未判定为成功".to_owned(),
            },
        },
    }
}

/// Checks whether a hostname-based HTTPS request can traverse this SOCKS5 endpoint.
/// This does not prove that a browser, WebRTC, or system DNS has no leaks.
pub fn test_remote_dns_path(port: u16) -> DnsPathTestResult {
    let started = Instant::now();
    let proxy = format!("127.0.0.1:{port}");
    let output = Command::new("curl.exe")
        .args([
            "--connect-timeout",
            "5",
            "--max-time",
            "12",
            "--silent",
            "--show-error",
            "--output",
            "NUL",
            "--write-out",
            "%{http_code}",
            "--socks5-hostname",
            proxy.as_str(),
            "https://example.com/",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let elapsed_ms = started.elapsed().as_millis();
    match output {
        Err(_) => DnsPathTestResult {
            port,
            http_status: None,
            elapsed_ms,
            message: "无法运行 curl.exe；请确认 Windows curl 可用".to_owned(),
        },
        Ok(output) if !output.status.success() => DnsPathTestResult {
            port,
            http_status: None,
            elapsed_ms,
            message: format!(
                "远程解析请求失败（curl 退出码 {:?}）；此结果不能单独区分 DNS 与代理故障",
                output.status.code()
            ),
        },
        Ok(output) => {
            let code = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u16>()
                .ok();
            let message = match code {
                Some(200..=399) => {
                    "SOCKS5 hostname 模式 HTTPS 请求成功；不代表浏览器 DNS/WebRTC 无泄漏".to_owned()
                }
                Some(status) => format!("收到 HTTP {status}；未判定为 DNS 诊断成功"),
                None => "未能读取 HTTP 状态码；未判定为成功".to_owned(),
            };
            DnsPathTestResult {
                port,
                http_status: code,
                elapsed_ms,
                message,
            }
        }
    }
}

fn parse_ip_response(bytes: &[u8]) -> Option<IpAddr> {
    IpAddr::from_str(std::str::from_utf8(bytes).ok()?.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_history_persists_only_sanitized_bounded_records() {
        let path = std::env::temp_dir().join(format!(
            "proxypilot-diagnostics-{}.json",
            uuid::Uuid::new_v4()
        ));
        let record = DiagnosticRecord {
            checked_at_unix: 1,
            kind: "egress_ip".to_owned(),
            port: 18001,
            success: true,
            egress_ip: Some("203.0.113.9".to_owned()),
            http_status: None,
            elapsed_ms: 123,
            message: "ok".to_owned(),
        };
        save_history_to(&path, &[record.clone()]).unwrap();
        save_history_to(&path, &[record]).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        let parsed: Vec<DiagnosticRecord> = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(!raw.contains("password"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn parses_ipv4_and_ipv6_responses() {
        assert_eq!(
            parse_ip_response(b" 203.0.113.7\n"),
            Some("203.0.113.7".parse().unwrap())
        );
        assert_eq!(
            parse_ip_response(b"2001:db8::1"),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn rejects_non_ip_or_malformed_response() {
        assert_eq!(parse_ip_response(b""), None);
        assert_eq!(parse_ip_response(b"not an ip"), None);
        assert_eq!(parse_ip_response(b"<html>"), None);
    }
}
