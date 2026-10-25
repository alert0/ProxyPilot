use percent_encoding::percent_decode_str;
use std::fmt;
use url::Url;

/// Parsed HY2 connection data. Secret fields are deliberately redacted in Debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct Hy2Node {
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    pub obfs_type: Option<String>,
    pub obfs_password: Option<String>,
    pub warnings: Vec<Hy2Warning>,
}

impl fmt::Debug for Hy2Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hy2Node")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("server_port", &self.server_port)
            .field("password", &"[REDACTED]")
            .field("sni", &self.sni)
            .field("insecure", &self.insecure)
            .field("obfs_type", &self.obfs_type)
            .field(
                "obfs_password",
                &self.obfs_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("warnings", &self.warnings)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hy2Warning {
    /// Parameter name only. Never include its value because it may contain credentials.
    pub parameter: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hy2ParseError {
    InvalidUrl,
    UnsupportedScheme,
    MissingServer,
    MissingPort,
    InvalidPort,
    MissingPassword,
    UnsupportedUserInfo,
    InvalidEncoding,
    InvalidBooleanParameter,
}

impl fmt::Display for Hy2ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidUrl => "分享链接格式无效",
            Self::UnsupportedScheme => "仅支持 hy2:// 分享链接",
            Self::MissingServer => "分享链接缺少服务器地址",
            Self::MissingPort => "分享链接缺少服务器端口",
            Self::InvalidPort => "服务器端口无效",
            Self::MissingPassword => "分享链接缺少认证密码",
            Self::UnsupportedUserInfo => "暂不支持包含用户名与密码分段的 userinfo 格式",
            Self::InvalidEncoding => "分享链接包含无效的编码文本",
            Self::InvalidBooleanParameter => "insecure 参数必须是 true/false 或 1/0",
        };
        f.write_str(message)
    }
}

impl std::error::Error for Hy2ParseError {}

/// Parse one Hysteria 2 share link.
///
/// The raw URL is never stored or included in errors. Unknown query parameters are
/// reported by name only, and credentials are redacted from Debug output.
pub fn parse_hy2_link(input: &str) -> Result<Hy2Node, Hy2ParseError> {
    let trimmed = input.trim();
    if !trimmed
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("hy2://"))
    {
        return Err(Hy2ParseError::UnsupportedScheme);
    }

    let url = Url::parse(trimmed).map_err(|_| Hy2ParseError::InvalidUrl)?;
    if url.scheme() != "hy2" {
        return Err(Hy2ParseError::UnsupportedScheme);
    }

    let server = url.host_str().ok_or(Hy2ParseError::MissingServer)?;
    if server.is_empty() {
        return Err(Hy2ParseError::MissingServer);
    }
    let server = server
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(server)
        .to_owned();

    let server_port = url.port().ok_or(Hy2ParseError::MissingPort)?;

    // Hysteria 2 share links conventionally place the auth password before '@'.
    // A colon in userinfo is ambiguous with URL username:password syntax, so fail
    // closed rather than silently changing the credential.
    if url.password().is_some() {
        return Err(Hy2ParseError::UnsupportedUserInfo);
    }
    let password = percent_decode_str(url.username())
        .decode_utf8()
        .map_err(|_| Hy2ParseError::InvalidEncoding)?
        .into_owned();
    if password.is_empty() {
        return Err(Hy2ParseError::MissingPassword);
    }

    let name = match url.fragment() {
        Some(fragment) if !fragment.is_empty() => percent_decode_str(fragment)
            .decode_utf8()
            .map_err(|_| Hy2ParseError::InvalidEncoding)?
            .into_owned(),
        _ => format!("{server}:{server_port}"),
    };

    let mut sni = None;
    let mut insecure = false;
    let mut obfs_type = None;
    let mut obfs_password = None;
    let mut warnings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (key, value) in url.query_pairs() {
        let key = key.into_owned();
        let value = value.into_owned();
        if !seen.insert(key.clone()) {
            warnings.push(Hy2Warning {
                parameter: key.clone(),
                message: "参数重复；当前仅保留最后一个值".to_owned(),
            });
        }

        match key.as_str() {
            "sni" => sni = non_empty(value),
            "insecure" => {
                insecure = match value.to_ascii_lowercase().as_str() {
                    "1" | "true" => true,
                    "0" | "false" | "" => false,
                    _ => return Err(Hy2ParseError::InvalidBooleanParameter),
                };
            }
            "obfs" => obfs_type = non_empty(value),
            "obfs-password" => obfs_password = non_empty(value),
            // These parameters are intentionally not mapped in M1. We surface
            // their names so users know that a future core adapter must review them.
            "pinSHA256" | "mport" | "ports" | "hopInterval" => {
                warnings.push(Hy2Warning {
                    parameter: key,
                    message: "该参数尚未在当前版本映射到 sing-box 配置".to_owned(),
                });
            }
            _ => warnings.push(Hy2Warning {
                parameter: key,
                message: "未知参数；当前版本不会应用此参数".to_owned(),
            }),
        }
    }

    if obfs_type.is_some() != obfs_password.is_some() {
        warnings.push(Hy2Warning {
            parameter: "obfs".to_owned(),
            message: "混淆类型与混淆密码应同时提供；请核对分享链接".to_owned(),
        });
    }

    Ok(Hy2Node {
        name,
        server,
        server_port,
        password,
        sni,
        insecure,
        obfs_type,
        obfs_password,
        warnings,
    })
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_link_and_encoded_name() {
        let node = parse_hy2_link(
            "hy2://test%40password@example.com:443/?sni=edge.example.com&insecure=0#Node%20One",
        )
        .expect("fixture should parse");

        assert_eq!(node.name, "Node One");
        assert_eq!(node.server, "example.com");
        assert_eq!(node.server_port, 443);
        assert_eq!(node.password, "test@password");
        assert_eq!(node.sni.as_deref(), Some("edge.example.com"));
        assert!(!node.insecure);
    }

    #[test]
    fn parses_ipv6_host() {
        let node = parse_hy2_link("hy2://secret@[2001:db8::1]:8443#ipv6").unwrap();
        assert_eq!(node.server, "2001:db8::1");
        assert_eq!(node.server_port, 8443);
    }

    #[test]
    fn parses_salamander_obfuscation() {
        let node = parse_hy2_link(
            "hy2://secret@example.com:443/?obfs=salamander&obfs-password=hidden#obfuscated",
        )
        .unwrap();
        assert_eq!(node.obfs_type.as_deref(), Some("salamander"));
        assert_eq!(node.obfs_password.as_deref(), Some("hidden"));
        assert!(node.warnings.is_empty());
    }

    #[test]
    fn rejects_wrong_scheme_without_echoing_input() {
        let secret_link = "https://super-secret@example.com:443";
        let error = parse_hy2_link(secret_link).unwrap_err();
        assert_eq!(error, Hy2ParseError::UnsupportedScheme);
        assert!(!error.to_string().contains("super-secret"));
    }

    #[test]
    fn rejects_missing_password() {
        assert_eq!(
            parse_hy2_link("hy2://example.com:443").unwrap_err(),
            Hy2ParseError::MissingPassword
        );
    }

    #[test]
    fn rejects_missing_port() {
        assert_eq!(
            parse_hy2_link("hy2://secret@example.com").unwrap_err(),
            Hy2ParseError::MissingPort
        );
    }

    #[test]
    fn rejects_invalid_insecure_value() {
        assert_eq!(
            parse_hy2_link("hy2://secret@example.com:443?insecure=maybe").unwrap_err(),
            Hy2ParseError::InvalidBooleanParameter
        );
    }

    #[test]
    fn unknown_parameters_are_reported_without_values() {
        let node =
            parse_hy2_link("hy2://secret@example.com:443?custom=do-not-log-this-value").unwrap();
        assert_eq!(node.warnings.len(), 1);
        assert_eq!(node.warnings[0].parameter, "custom");
        assert!(!format!("{:?}", node).contains("do-not-log-this-value"));
    }

    #[test]
    fn debug_redacts_credentials() {
        let node = parse_hy2_link(
            "hy2://super-secret@example.com:443/?obfs=salamander&obfs-password=secret-obfs",
        )
        .unwrap();
        let debug = format!("{node:?}");
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("secret-obfs"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn rejects_ambiguous_userinfo() {
        assert_eq!(
            parse_hy2_link("hy2://user:secret@example.com:443").unwrap_err(),
            Hy2ParseError::UnsupportedUserInfo
        );
    }
}
