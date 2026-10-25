use crate::nodes::{parse_hy2_link, Hy2Node};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::PathBuf};

const MAX_NODES: usize = 10;
const VAULT_SERVICE: &str = "ProxyPilot";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecord {
    pub id: String,
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub enabled: bool,
    pub sni: Option<String>,
    pub insecure: bool,
    pub obfs_type: Option<String>,
    pub warnings: Vec<String>,
    pub profile_name: String,
    pub listen_port: u16,
    pub secret_key: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeSecret {
    pub password: String,
    pub obfs_password: Option<String>,
}

pub trait SecretVault: Send {
    fn set(&self, key: &str, value: &str) -> Result<(), String>;
    fn get(&self, key: &str) -> Result<String, String>;
    fn delete(&self, key: &str) -> Result<(), String>;
}

pub struct WindowsCredentialVault;

impl SecretVault for WindowsCredentialVault {
    fn set(&self, key: &str, value: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(VAULT_SERVICE, key)
            .map_err(|_| "无法访问 Windows 凭据管理器".to_owned())?;
        entry
            .set_password(value)
            .map_err(|_| "无法将节点凭据保存到 Windows 凭据管理器".to_owned())
    }

    fn get(&self, key: &str) -> Result<String, String> {
        let entry = keyring::Entry::new(VAULT_SERVICE, key)
            .map_err(|_| "无法访问 Windows 凭据管理器".to_owned())?;
        entry
            .get_password()
            .map_err(|_| "节点凭据不存在或无法读取，请重新导入该节点".to_owned())
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(VAULT_SERVICE, key)
            .map_err(|_| "无法访问 Windows 凭据管理器".to_owned())?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            // A missing credential is already in the desired state.
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err("无法从 Windows 凭据管理器删除节点凭据".to_owned()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct NodeFile {
    version: u32,
    nodes: Vec<NodeRecord>,
}

pub struct NodeStore {
    path: PathBuf,
    nodes: Vec<NodeRecord>,
    vault: Box<dyn SecretVault>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddNodeResult {
    Added(String),
    Duplicate(String),
    LimitReached,
}

impl NodeStore {
    pub fn open_default() -> Result<Self, String> {
        let dirs = ProjectDirs::from("com", "alert0", "ProxyPilot")
            .ok_or_else(|| "无法确定 Windows 本地应用数据目录".to_owned())?;
        Self::open_with(
            dirs.config_dir().join("nodes.json"),
            Box::new(WindowsCredentialVault),
        )
    }

    pub fn open_with(path: PathBuf, vault: Box<dyn SecretVault>) -> Result<Self, String> {
        let nodes = if path.exists() {
            let raw = fs::read_to_string(&path).map_err(|_| "无法读取本地节点清单".to_owned())?;
            let file: NodeFile = serde_json::from_str(&raw)
                .map_err(|_| "本地节点清单格式无效；原文件已保留，请检查或备份".to_owned())?;
            if file.version != 1 {
                return Err("本地节点清单版本不受支持".to_owned());
            }
            if file.nodes.len() > MAX_NODES {
                return Err("本地节点清单超过当前版本支持的 10 个节点".to_owned());
            }
            validate_records(&file.nodes)?;
            file.nodes
        } else {
            Vec::new()
        };
        Ok(Self { path, nodes, vault })
    }

    pub fn nodes(&self) -> &[NodeRecord] {
        &self.nodes
    }

    pub fn add(&mut self, node: Hy2Node) -> Result<AddNodeResult, String> {
        for existing in self.nodes.iter().filter(|saved| {
            saved.server.eq_ignore_ascii_case(&node.server)
                && saved.server_port == node.server_port
                && saved.name == node.name
                && saved.sni == node.sni
                && saved.insecure == node.insecure
                && saved.obfs_type == node.obfs_type
                && saved.warnings
                    == node
                        .warnings
                        .iter()
                        .map(|w| w.parameter.clone())
                        .collect::<Vec<_>>()
        }) {
            let raw = match self.vault.get(&existing.secret_key) {
                Ok(raw) => raw,
                Err(_) => {
                    let secret = NodeSecret {
                        password: node.password.clone(),
                        obfs_password: node.obfs_password.clone(),
                    };
                    self.vault.set(
                        &existing.secret_key,
                        &serde_json::to_string(&secret).map_err(|_| "无法序列化凭据")?,
                    )?;
                    return Ok(AddNodeResult::Added(existing.id.clone()));
                }
            };
            let saved_secret: NodeSecret = serde_json::from_str(&raw)
                .map_err(|_| "现有节点凭据格式无效，无法安全检查重复项".to_owned())?;
            if saved_secret.password == node.password
                && saved_secret.obfs_password == node.obfs_password
            {
                return Ok(AddNodeResult::Duplicate(existing.id.clone()));
            }
        }
        if self.nodes.len() >= MAX_NODES {
            return Ok(AddNodeResult::LimitReached);
        }

        let id = uuid::Uuid::new_v4().to_string();
        let secret_key = format!("node-{id}");
        let secret = NodeSecret {
            password: node.password,
            obfs_password: node.obfs_password,
        };
        let secret_json =
            serde_json::to_string(&secret).map_err(|_| "无法序列化节点凭据".to_owned())?;
        let listen_port = (18001..=18010)
            .find(|port| self.nodes.iter().all(|saved| saved.listen_port != *port))
            .ok_or_else(|| "没有可分配的本地端口，请先删除一个节点".to_owned())?;
        let profile_number = listen_port - 18000;
        let record = NodeRecord {
            id: id.clone(),
            name: node.name,
            server: node.server,
            server_port: node.server_port,
            enabled: true,
            sni: node.sni,
            insecure: node.insecure,
            obfs_type: node.obfs_type,
            warnings: node
                .warnings
                .into_iter()
                .map(|warning| warning.parameter)
                .collect(),
            profile_name: format!("Profile {profile_number:02}"),
            listen_port,
            secret_key: secret_key.clone(),
        };
        self.vault.set(&secret_key, &secret_json)?;
        self.nodes.push(record);
        if let Err(error) = self.save() {
            self.nodes.pop();
            let _ = self.vault.delete(&format!("node-{id}"));
            return Err(error);
        }
        Ok(AddNodeResult::Added(id))
    }

    pub fn rename(&mut self, id: &str, name: &str) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("节点名称不能为空".to_owned());
        }
        if name.chars().count() > 80 {
            return Err("节点名称不能超过 80 个字符".to_owned());
        }
        let node = self
            .nodes
            .iter_mut()
            .find(|node| node.id == id)
            .ok_or_else(|| "找不到要修改的节点".to_owned())?;
        let previous = node.name.clone();
        node.name = name.to_owned();
        if let Err(error) = self.save() {
            self.nodes.iter_mut().find(|n| n.id == id).unwrap().name = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<(), String> {
        let node = self
            .nodes
            .iter_mut()
            .find(|node| node.id == id)
            .ok_or_else(|| "找不到要修改的节点".to_owned())?;
        let previous = node.enabled;
        node.enabled = enabled;
        if let Err(error) = self.save() {
            self.nodes.iter_mut().find(|n| n.id == id).unwrap().enabled = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn set_mapping(&mut self, id: &str, profile: &str, port: u16) -> Result<(), String> {
        if port == 0 || profile.trim().is_empty() || profile.chars().count() > 80 {
            return Err("Profile 名称须为 1–80 字，端口须为 1–65535".into());
        }
        if self
            .nodes
            .iter()
            .any(|n| n.id != id && n.listen_port == port)
        {
            return Err("本地端口已分配给其他 Profile".into());
        }
        let previous = self.nodes.clone();
        let node = self
            .nodes
            .iter_mut()
            .find(|n| n.id == id)
            .ok_or("找不到所选节点")?;
        node.profile_name = profile.trim().into();
        node.listen_port = port;
        if let Err(error) = self.save() {
            self.nodes = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Metadata only: credentials remain in this Windows user's vault.
    pub fn backup(&self, path: &std::path::Path) -> Result<(), String> {
        crate::settings::write_json(
            path,
            &NodeFile {
                version: 1,
                nodes: self.nodes.clone(),
            },
        )
    }

    /// Validate before replacing anything. On another PC credentials must be
    /// re-imported; restoring metadata never claims to restore secrets.
    pub fn restore(&mut self, path: &std::path::Path) -> Result<(), String> {
        if fs::metadata(path).map_err(|_| "无法读取备份")?.len() > 1_048_576 {
            return Err("备份超过 1 MiB".into());
        }
        let file: NodeFile = serde_json::from_slice(&fs::read(path).map_err(|_| "无法读取备份")?)
            .map_err(|_| "备份格式无效")?;
        if file.version != 1 {
            return Err("备份版本不受支持".into());
        }
        validate_records(&file.nodes)?;
        let previous = std::mem::replace(&mut self.nodes, file.nodes);
        if let Err(error) = self.save() {
            self.nodes = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn delete(&mut self, id: &str) -> Result<(), String> {
        let index = self
            .nodes
            .iter()
            .position(|node| node.id == id)
            .ok_or_else(|| "找不到要删除的节点".to_owned())?;
        let record = self.nodes.remove(index);
        if let Err(error) = self.save() {
            self.nodes.insert(index, record);
            return Err(error);
        }
        if let Err(error) = self.vault.delete(&record.secret_key) {
            self.nodes.insert(index, record);
            self.save()
                .map_err(|_| "凭据删除失败，元数据回滚也失败，请从备份恢复")?;
            return Err(error);
        }
        Ok(())
    }

    pub fn secret_for(&self, id: &str) -> Result<NodeSecret, String> {
        let record = self
            .nodes
            .iter()
            .find(|node| node.id == id)
            .ok_or_else(|| "找不到目标节点".to_owned())?;
        let raw = self.vault.get(&record.secret_key)?;
        serde_json::from_str(&raw).map_err(|_| "节点凭据格式无效，请重新导入".to_owned())
    }

    pub fn import_text(&mut self, text: &str) -> ImportSummary {
        let mut summary = ImportSummary::default();
        let decoded = match crate::nodes::decode_import_text(text) {
            Ok(value) => value,
            Err(error) => {
                summary.errors.push(error.to_string());
                return summary;
            }
        };
        for (line_index, line) in decoded.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match parse_hy2_link(line) {
                Err(error) => summary
                    .errors
                    .push(format!("第 {} 行：{}", line_index + 1, error)),
                Ok(node) => {
                    let warnings = node.warnings.len();
                    let name = node.name.clone();
                    match self.add(node) {
                        Ok(AddNodeResult::Added(id)) => {
                            summary.added.push((id, name));
                            summary.warning_count += warnings;
                        }
                        Ok(AddNodeResult::Duplicate(_)) => summary.duplicates += 1,
                        Ok(AddNodeResult::LimitReached) => {
                            summary.limit_reached = true;
                            break;
                        }
                        Err(error) => {
                            summary.errors.push(error);
                            break;
                        }
                    }
                }
            }
        }
        summary
    }

    fn save(&self) -> Result<(), String> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "本地节点清单路径无效".to_owned())?;
        fs::create_dir_all(parent).map_err(|_| "无法创建本地应用数据目录".to_owned())?;
        let file = NodeFile {
            version: 1,
            nodes: self.nodes.clone(),
        };
        let json =
            serde_json::to_vec_pretty(&file).map_err(|_| "无法序列化本地节点清单".to_owned())?;
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut output =
                fs::File::create(&tmp).map_err(|_| "无法写入本地节点清单临时文件".to_owned())?;
            output
                .write_all(&json)
                .map_err(|_| "无法写入本地节点清单".to_owned())?;
            output
                .sync_all()
                .map_err(|_| "无法刷新本地节点清单".to_owned())?;
        }
        fs::rename(&tmp, &self.path).map_err(|_| "无法原子替换本地节点清单".to_owned())
    }
}

fn validate_records(nodes: &[NodeRecord]) -> Result<(), String> {
    if nodes.len() > MAX_NODES {
        return Err("节点数超过 10 个".into());
    }
    let mut ids = std::collections::HashSet::new();
    let mut ports = std::collections::HashSet::new();
    for node in nodes {
        if uuid::Uuid::parse_str(&node.id).is_err()
            || node.secret_key != format!("node-{}", node.id)
            || !ids.insert(&node.id)
            || node.listen_port == 0
            || !ports.insert(node.listen_port)
            || node.server.is_empty()
            || node.server_port == 0
            || node.name.trim().is_empty()
            || node.name.chars().count() > 80
            || node.profile_name.trim().is_empty()
        {
            return Err("节点清单含重复项或无效的身份、端口及名称".into());
        }
    }
    Ok(())
}

impl std::fmt::Debug for NodeSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodeSecret([REDACTED])")
    }
}

#[derive(Default, Debug)]
pub struct ImportSummary {
    pub added: Vec<(String, String)>,
    pub duplicates: usize,
    pub warning_count: usize,
    pub errors: Vec<String>,
    pub limit_reached: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::HashMap};

    #[derive(Default)]
    struct MemoryVault(RefCell<HashMap<String, String>>);

    impl SecretVault for MemoryVault {
        fn set(&self, key: &str, value: &str) -> Result<(), String> {
            self.0.borrow_mut().insert(key.to_owned(), value.to_owned());
            Ok(())
        }
        fn get(&self, key: &str) -> Result<String, String> {
            self.0
                .borrow()
                .get(key)
                .cloned()
                .ok_or_else(|| "missing".to_owned())
        }
        fn delete(&self, key: &str) -> Result<(), String> {
            self.0.borrow_mut().remove(key);
            Ok(())
        }
    }

    fn temp_path() -> PathBuf {
        std::env::temp_dir().join(format!("proxypilot-{}.json", uuid::Uuid::new_v4()))
    }

    fn test_store() -> NodeStore {
        NodeStore::open_with(temp_path(), Box::<MemoryVault>::default()).unwrap()
    }

    #[test]
    fn mapping_changes_reject_duplicates_and_persist_custom_ports() {
        let mut store = test_store();
        store.import_text("hy2://first@example.com:443#One\nhy2://second@example.org:443#Two");
        let first = store.nodes()[0].id.clone();
        assert!(store.set_mapping(&first, "Browser A", 18002).is_err());
        assert!(store.set_mapping(&first, "Browser A", 0).is_err());
        store.set_mapping(&first, "Browser A", 24567).unwrap();
        assert_eq!(store.nodes()[0].listen_port, 24567);
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(&store.path).unwrap()).unwrap();
        assert_eq!(raw["nodes"][0]["profile_name"], "Browser A");
        let _ = fs::remove_file(&store.path);
    }

    #[test]
    fn failed_metadata_save_rolls_back_in_memory() {
        let mut store = test_store();
        store.import_text("hy2://fixture@example.com:443#Before");
        let before = store.nodes().to_vec();
        let original = store.path.clone();
        // A file cannot serve as a parent directory.
        store.path = original.join("cannot-write.json");
        assert!(store.rename(&before[0].id, "After").is_err());
        assert_eq!(store.nodes(), before);
        assert!(store.set_enabled(&before[0].id, false).is_err());
        assert_eq!(store.nodes(), before);
        assert!(store.set_mapping(&before[0].id, "After", 20000).is_err());
        assert_eq!(store.nodes(), before);
        let _ = fs::remove_file(original);
    }

    #[test]
    fn metadata_backup_restore_excludes_passwords_and_repairs_missing_credentials() {
        let mut store = test_store();
        store.import_text("hysteria2://fixture-secret@example.com:443#Node");
        let backup = temp_path();
        store.backup(&backup).unwrap();
        assert!(!fs::read_to_string(&backup)
            .unwrap()
            .contains("fixture-secret"));
        let mut restored = test_store();
        restored.restore(&backup).unwrap();
        let id = restored.nodes()[0].id.clone();
        assert!(restored.secret_for(&id).is_err());
        let summary = restored.import_text("hysteria2://fixture-secret@example.com:443#Node");
        assert_eq!(summary.added.len(), 1);
        assert_eq!(restored.nodes().len(), 1);
        assert_eq!(restored.nodes()[0].id, id);
        assert_eq!(restored.secret_for(&id).unwrap().password, "fixture-secret");
        let mut invalid: serde_json::Value =
            serde_json::from_slice(&fs::read(&backup).unwrap()).unwrap();
        invalid["nodes"][0]["secret_key"] = serde_json::json!("another-app-key");
        fs::write(&backup, serde_json::to_vec(&invalid).unwrap()).unwrap();
        let before = restored.nodes().to_vec();
        assert!(restored.restore(&backup).is_err());
        assert_eq!(restored.nodes(), before);
        for path in [&store.path, &restored.path, &backup] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn same_endpoint_different_tls_is_not_a_duplicate() {
        let mut store = test_store();
        let summary = store.import_text("hy2://fixture@example.com:443?sni=one.example#Node\nhy2://fixture@example.com:443?sni=two.example#Node");
        assert_eq!(summary.added.len(), 2);
        let _ = fs::remove_file(&store.path);
    }

    #[test]
    fn imports_nodes_persists_only_metadata_and_detects_duplicates() {
        let path = temp_path();
        let mut store = NodeStore::open_with(path.clone(), Box::<MemoryVault>::default()).unwrap();
        let summary = store.import_text(
            "hy2://fake-password@example.com:443#Node%201\nhy2://fake-password@example.com:443#Node%201",
        );
        assert_eq!(summary.added.len(), 1);
        assert_eq!(summary.duplicates, 1);
        assert_eq!(store.nodes().len(), 1);
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("fake-password"));
        assert!(!raw.contains("other-password"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn same_endpoint_and_name_with_different_credentials_is_not_a_duplicate() {
        let mut store = test_store();
        let summary = store.import_text(
            "hy2://first-password@example.com:443#Node\nhy2://second-password@example.com:443#Node",
        );
        assert_eq!(summary.added.len(), 2);
        assert_eq!(summary.duplicates, 0);
        assert_eq!(store.nodes()[0].listen_port, 18001);
        assert_eq!(store.nodes()[1].listen_port, 18002);
        let _ = fs::remove_file(&store.path);
    }

    #[test]
    fn supports_rename_enable_disable_and_delete() {
        let mut store = test_store();
        let summary = store.import_text("hy2://fake-password@example.com:443#Node");
        let id = &summary.added[0].0;
        store.rename(id, "Renamed").unwrap();
        store.set_enabled(id, false).unwrap();
        assert_eq!(store.nodes()[0].name, "Renamed");
        assert!(!store.nodes()[0].enabled);
        store.delete(id).unwrap();
        assert!(store.nodes().is_empty());
        let _ = fs::remove_file(&store.path);
    }

    #[test]
    fn caps_node_count_at_ten() {
        let mut store = test_store();
        for port in 10000..10010 {
            let input = format!("hy2://secret@example.com:{port}#node-{port}");
            let result = store.import_text(&input);
            assert_eq!(result.added.len(), 1);
        }
        let result = store.import_text("hy2://secret@example.com:20000#eleventh");
        assert!(result.limit_reached);
        assert_eq!(store.nodes().len(), MAX_NODES);
        let _ = fs::remove_file(&store.path);
    }

    #[test]
    fn secret_is_retrievable_from_vault_but_not_metadata() {
        let path = temp_path();
        let vault = Box::<MemoryVault>::default();
        let mut store = NodeStore::open_with(path.clone(), vault).unwrap();
        let summary = store.import_text("hy2://super-secret@example.com:443#node");
        assert_eq!(summary.added.len(), 1);
        assert_eq!(
            store.secret_for(&summary.added[0].0).unwrap().password,
            "super-secret"
        );
        let _ = fs::remove_file(path);
    }
}
