use std::{
    net::IpAddr,
    process::{Command, Stdio},
    str::FromStr,
    time::Instant,
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
                    "SOCKS5 hostname 模式 HTTPS 请求成功；不代表浏览器 DNS/WebRTC 无泄漏"
                        .to_owned()
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
