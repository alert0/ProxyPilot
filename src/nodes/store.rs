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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeSecret {
    pub password: String,
    pub obfs_password: Option<String>,
}

pub trait SecretVault {
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
        if let Some(existing) = self.nodes.iter().find(|saved| {
            saved.server.eq_ignore_ascii_case(&node.server)
                && saved.server_port == node.server_port
                && saved.name == node.name
        }) {
            return Ok(AddNodeResult::Duplicate(existing.id.clone()));
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
        if let Err(error) = self.vault.set(&secret_key, &secret_json) {
            return Err(error);
        }
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
        node.name = name.to_owned();
        self.save()
    }

    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<(), String> {
        let node = self
            .nodes
            .iter_mut()
            .find(|node| node.id == id)
            .ok_or_else(|| "找不到要修改的节点".to_owned())?;
        node.enabled = enabled;
        self.save()
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
        self.vault.delete(&record.secret_key)
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
    fn imports_nodes_persists_only_metadata_and_detects_duplicates() {
        let path = temp_path();
        let mut store = NodeStore::open_with(path.clone(), Box::<MemoryVault>::default()).unwrap();
        let summary = store.import_text(
            "hy2://fake-password@example.com:443#Node%201\nhy2://other-password@example.com:443#Node%201",
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
