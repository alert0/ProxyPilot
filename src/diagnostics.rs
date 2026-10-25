use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    net::IpAddr,
    process::Stdio,
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
    #[serde(default)]
    pub service: Option<String>,
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
            service: None,
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
            service: None,
            checked_at_unix: now_unix(),
            kind: "remote_dns_path".to_owned(),
            port: result.port,
            success: result
                .http_status
                .is_some_and(|status| (200..=399).contains(&status)),
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
    static HISTORY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = HISTORY_LOCK.lock().map_err(|_| "诊断历史锁不可用")?;
    let dirs = ProjectDirs::from("com", "alert0", "ProxyPilot")
        .ok_or_else(|| "无法确定本地诊断历史目录".to_owned())?;
    save_history_to(&dirs.config_dir().join("diagnostics.json"), records)
}

pub fn read_history() -> Result<Vec<DiagnosticRecord>, String> {
    let path = crate::settings::data_dir()?.join("diagnostics.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&fs::read(path).map_err(|_| "无法读取诊断历史")?)
        .map_err(|_| "诊断历史格式无效".into())
}

pub fn listener_available(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(200),
    )
    .is_ok()
}

fn classify_curl_error(code: Option<i32>) -> String {
    match code {
        Some(22) => "测试服务 HTTP 错误，不能据此判定节点故障".into(),
        Some(60) => "TLS 证书校验失败，未判定为成功".into(),
        Some(35) => "测试请求 TLS 握手失败：可能是目标服务或网络，未判定为节点故障".into(),
        Some(97) => "SOCKS 连接或远程解析失败".into(),
        Some(28) => "请求超时：可能是节点、网络或测试服务，尚不能确定故障来源".into(),
        Some(7) => "连接失败：请检查监听、节点及测试服务".into(),
        _ => format!("请求失败（退出码 {code:?}），未判定为节点故障"),
    }
}

/// At most four workers. Results preserve the input order.
pub fn batch(
    ports: &[u16],
    dns: bool,
    settings: &crate::settings::Settings,
) -> Vec<DiagnosticRecord> {
    let mut records = Vec::new();
    for group in ports.chunks(settings.concurrency.clamp(1, 4)) {
        let mut results = std::thread::scope(|scope| {
            let handles: Vec<_> = group
                .iter()
                .map(|&port| {
                    scope.spawn(move || {
                        if dns {
                            DiagnosticRecord::from(test_remote_dns_path_with(port, settings))
                        } else {
                            DiagnosticRecord::from(test_egress_ip_with(port, settings))
                        }
                    })
                })
                .collect();
            handles
                .into_iter()
                .filter_map(|h| h.join().ok())
                .collect::<Vec<_>>()
        });
        let service = url::Url::parse(if dns {
            &settings.dns_url
        } else {
            &settings.ip_url
        })
        .ok()
        .map(|url| url.origin().ascii_serialization());
        for result in &mut results {
            result.service = service.clone();
        }
        records.append(&mut results);
    }
    records
}

fn save_history_to(path: &std::path::Path, records: &[DiagnosticRecord]) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "诊断历史路径无效".to_owned())?;
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
    let json = serde_json::to_vec_pretty(&history).map_err(|_| "无法序列化诊断历史".to_owned())?;
    let temporary = path.with_extension("json.tmp");
    {
        let mut file =
            fs::File::create(&temporary).map_err(|_| "无法创建诊断历史临时文件".to_owned())?;
        file.write_all(&json)
            .map_err(|_| "无法写入诊断历史".to_owned())?;
        file.sync_all().map_err(|_| "无法刷新诊断历史".to_owned())?;
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
    test_egress_ip_with(port, &crate::settings::Settings::default())
}

pub fn test_egress_ip_with(port: u16, settings: &crate::settings::Settings) -> EgressTestResult {
    let started = Instant::now();
    let proxy = format!("127.0.0.1:{port}");
    if !listener_available(port) {
        return EgressTestResult {
            port,
            egress_ip: None,
            elapsed_ms: started.elapsed().as_millis(),
            message: "监听不可用：本地 SOCKS5 端口未开放".into(),
        };
    }
    let timeout = settings.timeout_seconds.to_string();
    let mut command = crate::process::command("curl.exe");
    command
        .args([
            "--disable",
            "--noproxy",
            "",
            "--proto",
            "=https",
            "--max-filesize",
            "65536",
            "--connect-timeout",
            "5",
            "--max-time",
            &timeout,
            "--silent",
            "--show-error",
            "--fail",
            "--socks5-hostname",
            proxy.as_str(),
            &settings.ip_url,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = crate::process::output(
        command,
        std::time::Duration::from_secs(settings.timeout_seconds + 2),
    );

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
            message: classify_curl_error(output.status.code()),
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
    test_remote_dns_path_with(port, &crate::settings::Settings::default())
}

pub fn test_remote_dns_path_with(
    port: u16,
    settings: &crate::settings::Settings,
) -> DnsPathTestResult {
    let started = Instant::now();
    let proxy = format!("127.0.0.1:{port}");
    if !listener_available(port) {
        return DnsPathTestResult {
            port,
            http_status: None,
            elapsed_ms: started.elapsed().as_millis(),
            message: "监听不可用：本地 SOCKS5 端口未开放".into(),
        };
    }
    let timeout = settings.timeout_seconds.to_string();
    let mut command = crate::process::command("curl.exe");
    command
        .args([
            "--disable",
            "--noproxy",
            "",
            "--proto",
            "=https",
            "--max-filesize",
            "65536",
            "--connect-timeout",
            "5",
            "--max-time",
            &timeout,
            "--silent",
            "--show-error",
            "--output",
            "NUL",
            "--write-out",
            "%{http_code}",
            "--socks5-hostname",
            proxy.as_str(),
            &settings.dns_url,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = crate::process::output(
        command,
        std::time::Duration::from_secs(settings.timeout_seconds + 2),
    );

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
            message: classify_curl_error(output.status.code()),
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
            service: Some("https://example.invalid".into()),
            checked_at_unix: 1,
            kind: "egress_ip".to_owned(),
            port: 18001,
            success: true,
            egress_ip: Some("203.0.113.9".to_owned()),
            http_status: None,
            elapsed_ms: 123,
            message: "ok".to_owned(),
        };
        save_history_to(&path, &vec![record.clone(); 505]).unwrap();
        save_history_to(&path, std::slice::from_ref(&record)).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        let parsed: Vec<DiagnosticRecord> = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.len(), 500);
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

    #[test]
    fn closed_listener_is_distinct_from_remote_failure() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(listener_available(port));
        drop(listener);
        let result = test_egress_ip(port);
        assert!(result.egress_ip.is_none());
        assert!(result.message.starts_with("监听不可用"));
        assert!(classify_curl_error(Some(22)).contains("测试服务"));
        assert!(!classify_curl_error(Some(28)).contains("节点故障"));
    }
}
