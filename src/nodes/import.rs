use base64::{engine::general_purpose, Engine as _};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportDecodeError {
    InvalidBase64,
    InvalidUtf8,
    EmptyInput,
}

impl fmt::Display for ImportDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBase64 => {
                "输入不是有效的 Base64 内容；也可直接粘贴 hy2:// 或 hysteria2:// 链接"
            }
            Self::InvalidUtf8 => "Base64 解码结果不是有效的 UTF-8 文本",
            Self::EmptyInput => "请粘贴 HY2 分享链接或 Base64 编码的链接列表",
        })
    }
}

impl std::error::Error for ImportDecodeError {}

/// Accept plain share links or a Base64 subscription body, entirely locally.
/// Errors never include the input or decoded credentials.
pub fn decode_import_text(input: &str) -> Result<String, ImportDecodeError> {
    let input = input.trim().trim_start_matches('\u{feff}').trim();
    if input.is_empty() {
        return Err(ImportDecodeError::EmptyInput);
    }
    // Keep plain links intact, including unsupported schemes for per-line errors.
    if input.contains("://") {
        return Ok(input.to_owned());
    }

    let compact: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let decoded = [
        general_purpose::STANDARD,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::URL_SAFE_NO_PAD,
    ]
    .iter()
    .find_map(|engine| engine.decode(&compact).ok())
    .ok_or(ImportDecodeError::InvalidBase64)?;
    let text = String::from_utf8(decoded).map_err(|_| ImportDecodeError::InvalidUtf8)?;
    let text = text.trim().trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        return Err(ImportDecodeError::EmptyInput);
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::{parse_hy2_link, Hy2ParseError};

    const LINKS: &str =
        "hy2://test@example.com:443#节点一\r\nhysteria2://other@example.org:8443#节点二";

    #[test]
    fn preserves_plain_links_and_handles_bom() {
        assert_eq!(
            decode_import_text(&format!("\u{feff} {LINKS}\n")).unwrap(),
            LINKS
        );
    }

    #[test]
    fn imports_all_base64_variants_with_wrapping() {
        // This suffix ensures standard and URL-safe alphabets differ, with padding needed.
        let links = format!("{LINKS}~");
        for engine in [
            general_purpose::STANDARD,
            general_purpose::STANDARD_NO_PAD,
            general_purpose::URL_SAFE,
            general_purpose::URL_SAFE_NO_PAD,
        ] {
            let encoded = engine.encode(&links);
            let wrapped = encoded
                .as_bytes()
                .chunks(13)
                .map(|chunk| std::str::from_utf8(chunk).unwrap())
                .collect::<Vec<_>>()
                .join("\r\n ");
            let decoded = decode_import_text(&wrapped).unwrap();
            assert_eq!(decoded, links);
            let nodes = decoded
                .lines()
                .map(parse_hy2_link)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(nodes.len(), 2);
            assert_eq!(nodes[0].name, "节点一");
            assert_eq!(nodes[1].server_port, 8443);
        }
    }

    #[test]
    fn decoded_links_still_require_validation() {
        let encoded = general_purpose::STANDARD.encode("hy2://example.com:443");
        assert_eq!(
            parse_hy2_link(&decode_import_text(&encoded).unwrap()).unwrap_err(),
            Hy2ParseError::MissingPassword
        );
    }

    #[test]
    fn invalid_content_never_echoes_input() {
        for (input, expected) in [
            ("sensitive-invalid!", ImportDecodeError::InvalidBase64),
            ("/w==", ImportDecodeError::InvalidUtf8),
            (" \n", ImportDecodeError::EmptyInput),
            ("IA==", ImportDecodeError::EmptyInput),
        ] {
            let error = decode_import_text(input).unwrap_err();
            assert_eq!(error, expected);
            assert!(!error.to_string().contains(input));
        }
    }

    #[test]
    fn preserves_mixed_plain_lines_for_individual_validation() {
        let input = "hy2://test@example.com:443\nhttps://example.com";
        let decoded = decode_import_text(input).unwrap();
        let results: Vec<_> = decoded.lines().map(parse_hy2_link).collect();
        assert!(results[0].is_ok());
        assert_eq!(results[1], Err(Hy2ParseError::UnsupportedScheme));
    }
}
