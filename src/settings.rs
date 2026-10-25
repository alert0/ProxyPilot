use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub fn data_dir() -> Result<PathBuf, String> {
    directories::ProjectDirs::from("com", "alert0", "ProxyPilot")
        .map(|dirs| dirs.config_dir().to_owned())
        .ok_or_else(|| "无法确定应用数据目录".to_owned())
}

pub fn instance_lock() -> Result<fs::File, String> {
    let directory = data_dir()?;
    fs::create_dir_all(&directory).map_err(|_| "无法创建应用目录")?;
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    options
        .open(directory.join("instance.lock"))
        .map_err(|_| "ProxyPilot 已在运行，或数据目录被占用".into())
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let parent = path.parent().ok_or("文件路径无效")?;
    fs::create_dir_all(parent).map_err(|_| "无法创建数据目录")?;
    let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let bytes = serde_json::to_vec_pretty(value).map_err(|_| "无法序列化数据")?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .map_err(|_| "无法创建临时文件")?;
        file.write_all(&bytes).map_err(|_| "无法写入数据")?;
        file.sync_all().map_err(|_| "无法刷新数据")?;
        drop(file);
        fs::rename(&tmp, path).map_err(|_| "无法替换数据文件")
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result.map_err(str::to_owned)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub core_path: Option<PathBuf>,
    pub core_sha256: Option<String>,
    pub ip_url: String,
    pub dns_url: String,
    pub concurrency: usize,
    pub timeout_seconds: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            core_path: None,
            core_sha256: None,
            ip_url: "https://icanhazip.com/".into(),
            dns_url: "https://example.com/".into(),
            concurrency: 3,
            timeout_seconds: 12,
        }
    }
}
impl Settings {
    pub fn load() -> Result<Self, String> {
        let path = data_dir()?.join("settings.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let value: Self = serde_json::from_slice(&fs::read(path).map_err(|_| "无法读取设置")?)
            .map_err(|_| "设置格式无效，原文件已保留")?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        for value in [&self.ip_url, &self.dns_url] {
            let url = url::Url::parse(value).map_err(|_| "测试服务 URL 无效")?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err("测试服务必须使用不含账号密码和片段的 HTTPS URL".into());
            }
        }
        if !(1..=4).contains(&self.concurrency) || !(3..=60).contains(&self.timeout_seconds) {
            return Err("并发数须为 1–4，超时须为 3–60 秒".into());
        }
        Ok(())
    }
    pub fn save(&self) -> Result<(), String> {
        self.validate()?;
        write_json(&data_dir()?.join("settings.json"), self)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub at: u64,
    pub event: String,
}
pub fn log(event: &str) {
    static LOG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let Ok(_guard) = LOG_LOCK.lock() else {
        return;
    };
    if let Ok(dir) = data_dir() {
        let path = dir.join("events.json");
        let mut logs = read_logs();
        logs.push(LogEntry {
            at: now(),
            event: event.chars().take(200).collect(),
        });
        if logs.len() > 500 {
            logs.drain(..logs.len() - 500);
        }
        let _ = write_json(&path, &logs);
    }
}
pub fn read_logs() -> Vec<LogEntry> {
    data_dir()
        .ok()
        .and_then(|p| fs::read(p.join("events.json")).ok())
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default()
}
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_reject_unsafe_urls_and_bounds() {
        for url in [
            "http://example.com",
            "https://user:secret@example.com",
            "file:///tmp/test",
            "https://example.com/#secret",
        ] {
            let settings = Settings {
                ip_url: url.into(),
                ..Default::default()
            };
            assert!(settings.validate().is_err());
        }
        assert!(Settings {
            concurrency: 0,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(Settings::default().validate().is_ok());
    }
}
