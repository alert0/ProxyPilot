use crate::nodes::{NodeRecord, NodeSecret};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    NoEnabledNodes,
    DuplicatePort(u16),
    InvalidPort(u16),
    MissingSecret(String),
    UnsupportedParameters(String, Vec<String>),
    InvalidObfuscation(String),
    InvalidRouteIsolation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEnabledNodes => f.write_str("没有启用的节点可生成配置"),
            Self::DuplicatePort(port) => write!(f, "本地监听端口 {port} 重复"),
            Self::InvalidPort(port) => write!(f, "本地监听端口 {port} 不在允许范围 18001–18010"),
            Self::MissingSecret(id) => write!(f, "节点 {id} 的凭据不可用，请重新导入该节点"),
            Self::UnsupportedParameters(id, names) => write!(
                f,
                "节点 {id} 含有当前版本尚未支持的参数：{}；为避免静默改变连接行为，已阻止生成配置",
                names.join(", ")
            ),
            Self::InvalidObfuscation(id) => {
                write!(f, "节点 {id} 的混淆类型和密码不完整，已阻止生成配置")
            }
            Self::InvalidRouteIsolation(reason) => {
                write!(f, "路由隔离校验失败：{reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Build a sing-box config in memory. Secrets are supplied by the caller (normally
/// Windows Credential Manager) and are never written to logs by this function.
pub fn generate_config(
    nodes: &[NodeRecord],
    mut secret_for: impl FnMut(&str) -> Result<NodeSecret, String>,
) -> Result<Value, ConfigError> {
    let enabled: Vec<&NodeRecord> = nodes.iter().filter(|node| node.enabled).collect();
    if enabled.is_empty() {
        return Err(ConfigError::NoEnabledNodes);
    }

    let mut ports = HashSet::new();
    let mut ids = HashSet::new();
    let mut inbounds = Vec::with_capacity(enabled.len());
    let mut outbounds = Vec::with_capacity(enabled.len());
    let mut rules = Vec::with_capacity(enabled.len());

    for node in enabled {
        if !(18001..=18010).contains(&node.listen_port) {
            return Err(ConfigError::InvalidPort(node.listen_port));
        }
        if !ports.insert(node.listen_port) {
            return Err(ConfigError::DuplicatePort(node.listen_port));
        }
        if !ids.insert(node.id.as_str()) {
            return Err(ConfigError::UnsupportedParameters(
                node.id.clone(),
                vec!["重复节点 ID".to_owned()],
            ));
        }
        if !node.warnings.is_empty() {
            return Err(ConfigError::UnsupportedParameters(
                node.id.clone(),
                node.warnings.clone(),
            ));
        }

        let secret =
            secret_for(&node.id).map_err(|_| ConfigError::MissingSecret(node.id.clone()))?;
        if node.obfs_type.is_some() != secret.obfs_password.is_some() {
            return Err(ConfigError::InvalidObfuscation(node.id.clone()));
        }

        let inbound_tag = format!("in-{}", node.id);
        let outbound_tag = format!("out-{}", node.id);
        let mut tls = Map::new();
        tls.insert("enabled".to_owned(), json!(true));
        if let Some(server_name) = &node.sni {
            if !server_name.is_empty() {
                tls.insert("server_name".to_owned(), json!(server_name));
            }
        }
        if node.insecure {
            tls.insert("insecure".to_owned(), json!(true));
        }

        let mut outbound = json!({
            "type": "hysteria2",
            "tag": outbound_tag,
            "server": node.server,
            "server_port": node.server_port,
            "password": secret.password,
            "tls": Value::Object(tls)
        });
        if let (Some(obfs_type), Some(obfs_password)) =
            (node.obfs_type.as_ref(), secret.obfs_password.as_ref())
        {
            outbound["obfs"] = json!({
                "type": obfs_type,
                "password": obfs_password
            });
        }

        inbounds.push(json!({
            "type": "socks",
            "tag": inbound_tag,
            "listen": "127.0.0.1",
            "listen_port": node.listen_port
        }));
        outbounds.push(outbound);
        rules.push(json!({
            "inbound": [inbound_tag],
            "action": "route",
            "outbound": outbound_tag
        }));
    }

    let config = json!({
        "log": { "level": "warn", "timestamp": true },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules
        }
    });
    validate_route_isolation(&config)?;
    Ok(config)
}

/// Ensure every local SOCKS inbound has exactly one explicit route to one unique
/// outbound. Selector/urltest groups and implicit fallback routing are rejected.
pub fn validate_route_isolation(config: &Value) -> Result<(), ConfigError> {
    let inbounds = config["inbounds"]
        .as_array()
        .ok_or_else(|| ConfigError::InvalidRouteIsolation("缺少 inbounds".to_owned()))?;
    let outbounds = config["outbounds"]
        .as_array()
        .ok_or_else(|| ConfigError::InvalidRouteIsolation("缺少 outbounds".to_owned()))?;
    let rules = config["route"]["rules"]
        .as_array()
        .ok_or_else(|| ConfigError::InvalidRouteIsolation("缺少显式 route.rules".to_owned()))?;

    if inbounds.is_empty() || inbounds.len() != outbounds.len() || rules.len() != inbounds.len() {
        return Err(ConfigError::InvalidRouteIsolation(
            "inbound、outbound 和 route rule 数量必须相同且非空".to_owned(),
        ));
    }

    let mut inbound_tags = HashSet::new();
    for inbound in inbounds {
        let tag = inbound["tag"]
            .as_str()
            .ok_or_else(|| ConfigError::InvalidRouteIsolation("入口缺少 tag".to_owned()))?;
        if !inbound_tags.insert(tag) {
            return Err(ConfigError::InvalidRouteIsolation(
                "入口 tag 重复".to_owned(),
            ));
        }
        if inbound["listen"] != "127.0.0.1" {
            return Err(ConfigError::InvalidRouteIsolation(
                "SOCKS 入口必须只监听 127.0.0.1".to_owned(),
            ));
        }
    }

    let mut outbound_tags = HashSet::new();
    for outbound in outbounds {
        let tag = outbound["tag"]
            .as_str()
            .ok_or_else(|| ConfigError::InvalidRouteIsolation("出站缺少 tag".to_owned()))?;
        if !outbound_tags.insert(tag) {
            return Err(ConfigError::InvalidRouteIsolation(
                "出站 tag 重复".to_owned(),
            ));
        }
        if matches!(outbound["type"].as_str(), Some("selector" | "urltest")) {
            return Err(ConfigError::InvalidRouteIsolation(
                "禁止 selector/urltest 自动切换出站".to_owned(),
            ));
        }
    }

    let mut used_inbounds = HashSet::new();
    let mut used_outbounds = HashSet::new();
    for rule in rules {
        if rule["action"] != "route" {
            return Err(ConfigError::InvalidRouteIsolation(
                "所有入口规则必须显式使用 route action".to_owned(),
            ));
        }
        let targets = rule["inbound"]
            .as_array()
            .ok_or_else(|| ConfigError::InvalidRouteIsolation("路由规则缺少 inbound".to_owned()))?;
        if targets.len() != 1 {
            return Err(ConfigError::InvalidRouteIsolation(
                "每条路由规则必须只匹配一个入口".to_owned(),
            ));
        }
        let inbound_tag = targets[0]
            .as_str()
            .ok_or_else(|| ConfigError::InvalidRouteIsolation("入口 tag 格式无效".to_owned()))?;
        let outbound_tag = rule["outbound"]
            .as_str()
            .ok_or_else(|| ConfigError::InvalidRouteIsolation("路由规则缺少 outbound".to_owned()))?;
        if !inbound_tags.contains(inbound_tag) || !outbound_tags.contains(outbound_tag) {
            return Err(ConfigError::InvalidRouteIsolation(
                "路由引用了不存在的入口或出站".to_owned(),
            ));
        }
        if !used_inbounds.insert(inbound_tag) || !used_outbounds.insert(outbound_tag) {
            return Err(ConfigError::InvalidRouteIsolation(
                "入口或出站被多条规则复用，无法保证一对一绑定".to_owned(),
            ));
        }
    }

    if used_inbounds.len() != inbounds.len() || used_outbounds.len() != outbounds.len() {
        return Err(ConfigError::InvalidRouteIsolation(
            "存在没有明确绑定路由的入口或出站".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(index: usize, port: u16) -> NodeRecord {
        NodeRecord {
            id: format!("node-{index}"),
            name: format!("Test {index}"),
            server: format!("node{index}.example.invalid"),
            server_port: 443,
            enabled: true,
            sni: Some("edge.example.invalid".to_owned()),
            insecure: false,
            obfs_type: None,
            warnings: Vec::new(),
            profile_name: format!("Profile {index:02}"),
            listen_port: port,
            secret_key: format!("secret-{index}"),
        }
    }

    fn secret(_: &str) -> Result<NodeSecret, String> {
        Ok(NodeSecret {
            password: "fixture-only-secret".to_owned(),
            obfs_password: None,
        })
    }

    #[test]
    fn generates_explicit_loopback_routes_for_one_two_and_ten_nodes() {
        for count in [1_usize, 2, 10] {
            let nodes: Vec<_> = (0..count)
                .map(|index| node(index, 18001 + index as u16))
                .collect();
            let config = generate_config(&nodes, secret).unwrap();
            assert_eq!(config["inbounds"].as_array().unwrap().len(), count);
            assert_eq!(config["outbounds"].as_array().unwrap().len(), count);
            assert_eq!(config["route"]["rules"].as_array().unwrap().len(), count);
            for (index, rule) in config["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
            {
                assert_eq!(rule["inbound"][0], format!("in-node-{index}"));
                assert_eq!(rule["outbound"], format!("out-node-{index}"));
            }
            assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        }
    }

    #[test]
    fn route_isolation_rejects_missing_or_automatic_fallback_routes() {
        let nodes = vec![node(0, 18001), node(1, 18002)];
        let config = generate_config(&nodes, secret).unwrap();

        let mut missing_rule = config.clone();
        missing_rule["route"]["rules"].as_array_mut().unwrap().pop();
        assert!(matches!(
            validate_route_isolation(&missing_rule),
            Err(ConfigError::InvalidRouteIsolation(_))
        ));

        let mut selector = config;
        selector["outbounds"][0]["type"] = json!("selector");
        assert!(matches!(
            validate_route_isolation(&selector),
            Err(ConfigError::InvalidRouteIsolation(_))
        ));
    }

    #[test]
    fn rejects_duplicate_ports_and_unknown_parameters() {
        let nodes = vec![node(0, 18001), node(1, 18001)];
        assert_eq!(
            generate_config(&nodes, secret).unwrap_err(),
            ConfigError::DuplicatePort(18001)
        );
        let mut unsupported = node(0, 18001);
        unsupported.warnings.push("pinSHA256".to_owned());
        assert_eq!(
            generate_config(&[unsupported], secret).unwrap_err(),
            ConfigError::UnsupportedParameters("node-0".to_owned(), vec!["pinSHA256".to_owned()])
        );
    }

    #[test]
    fn disabled_nodes_are_not_emitted_and_empty_config_is_rejected() {
        let mut disabled = node(0, 18001);
        disabled.enabled = false;
        assert_eq!(
            generate_config(&[disabled], secret).unwrap_err(),
            ConfigError::NoEnabledNodes
        );
    }

    #[test]
    fn emits_salamander_obfuscation_and_tls_options() {
        let mut configured = node(0, 18001);
        configured.obfs_type = Some("salamander".to_owned());
        configured.insecure = true;
        let config = generate_config(&[configured], |_| {
            Ok(NodeSecret {
                password: "fixture-password".to_owned(),
                obfs_password: Some("fixture-obfs-password".to_owned()),
            })
        })
        .unwrap();
        assert_eq!(config["outbounds"][0]["obfs"]["type"], "salamander");
        assert_eq!(config["outbounds"][0]["tls"]["insecure"], true);
    }
}
