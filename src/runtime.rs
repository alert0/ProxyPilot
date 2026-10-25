use crate::{config::generate_config, nodes::NodeStore};
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

pub struct RuntimeManager {
    core_path: Option<PathBuf>,
    config_path: PathBuf,
    child: Option<Child>,
    version: Option<String>,
}

impl RuntimeManager {
    pub fn new() -> Result<Self, String> {
        let dirs = directories::ProjectDirs::from("com", "alert0", "ProxyPilot")
            .ok_or_else(|| "无法确定应用数据目录".to_owned())?;
        Ok(Self {
            core_path: None,
            config_path: dirs.config_dir().join("runtime.json"),
            child: None,
            version: None,
        })
    }

    pub fn core_path(&self) -> Option<&PathBuf> {
        self.core_path.as_ref()
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn is_running(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) | Err(_) => {
                self.child = None;
                false
            }
        }
    }

    pub fn choose_core(&mut self, path: PathBuf) -> Result<String, String> {
        if !path.is_file() {
            return Err("所选 sing-box 文件不存在".to_owned());
        }
        if !path
            .extension()
            .is_some_and(|extension| extension.to_string_lossy().eq_ignore_ascii_case("exe"))
        {
            return Err("请选择 Windows 可执行文件（.exe）".to_owned());
        }
        let output = Command::new(&path)
            .arg("version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|_| "无法运行所选文件；请确认它是可执行的 sing-box.exe".to_owned())?;
        if !output.status.success() {
            return Err("所选文件未能通过 sing-box version 检查".to_owned());
        }
        let version_output = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !version_output.to_ascii_lowercase().contains("sing-box") {
            return Err("所选程序没有报告 sing-box 版本信息".to_owned());
        }
        let version = version_output
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("sing-box version unknown")
            .to_owned();
        self.core_path = Some(path);
        self.version = Some(version.clone());
        Ok(version)
    }

    pub fn validate_config(&self, config: &Value) -> Result<(), String> {
        let core = self
            .core_path
            .as_ref()
            .ok_or_else(|| "请先选择并验证 sing-box.exe".to_owned())?;
        self.write_config(config)?;
        let output = match Command::new(core)
            .arg("check")
            .arg("-c")
            .arg(&self.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            Ok(output) => output,
            Err(_) => {
                let _ = fs::remove_file(&self.config_path);
                return Err("无法启动 sing-box 配置校验进程".to_owned());
            }
        };
        if output.status.success() {
            Ok(())
        } else {
            let _ = fs::remove_file(&self.config_path);
            // Never echo raw core output: it can include server or configuration details.
            Err("sing-box check 未通过；请检查节点参数与所选核心版本。未启动代理。".to_owned())
        }
    }

    pub fn start(&mut self, store: &NodeStore) -> Result<String, String> {
        if self.is_running() {
            return Ok("ProxyPilot 管理的 sing-box 进程已经在运行".to_owned());
        }
        let core = self
            .core_path
            .clone()
            .ok_or_else(|| "请先选择并验证 sing-box.exe".to_owned())?;
        let config = generate_config(store.nodes(), |id| store.secret_for(id))
            .map_err(|error| error.to_string())?;
        self.check_ports_available(&config)?;
        self.validate_config(&config)?;

        let child = match Command::new(core)
            .arg("run")
            .arg("-c")
            .arg(&self.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => {
                let _ = fs::remove_file(&self.config_path);
                return Err("sing-box 启动失败；请确认程序权限与配置文件访问权限".to_owned());
            }
        };
        self.child = Some(child);
        if !self.is_running() {
            return Err("sing-box 启动后立即退出；请检查核心版本与配置".to_owned());
        }
        Ok(format!(
            "sing-box 已启动；配置文件位于本地应用数据目录（{} 个入口）。",
            config["inbounds"].as_array().map_or(0, Vec::len)
        ))
    }

    pub fn stop(&mut self) -> Result<String, String> {
        let Some(mut child) = self.child.take() else {
            return Ok("当前没有由 ProxyPilot 启动的 sing-box 进程".to_owned());
        };
        if child
            .try_wait()
            .map_err(|_| "无法检查 sing-box 进程状态".to_owned())?
            .is_some()
        {
            return Ok("sing-box 进程已经退出".to_owned());
        }
        child
            .kill()
            .map_err(|_| "无法停止 ProxyPilot 自己启动的 sing-box 进程".to_owned())?;
        child
            .wait()
            .map_err(|_| "等待 sing-box 退出失败".to_owned())?;
        let _ = fs::remove_file(&self.config_path);
        Ok("ProxyPilot 启动的 sing-box 进程已停止；其他进程未受影响".to_owned())
    }

    fn check_ports_available(&self, config: &Value) -> Result<(), String> {
        let inbounds = config["inbounds"]
            .as_array()
            .ok_or_else(|| "配置中缺少 SOCKS5 入口".to_owned())?;
        for inbound in inbounds {
            let port = inbound["listen_port"]
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| "配置中的监听端口无效".to_owned())?;
            TcpListener::bind(("127.0.0.1", port))
                .map_err(|_| format!("本地端口 {port} 已被占用；未结束或修改任何其他进程"))?;
        }
        Ok(())
    }

    fn write_config(&self, config: &Value) -> Result<(), String> {
        let parent = self
            .config_path
            .parent()
            .ok_or_else(|| "配置文件路径无效".to_owned())?;
        fs::create_dir_all(parent).map_err(|_| "无法创建本地配置目录".to_owned())?;
        secure_config_directory(parent)?;
        let data =
            serde_json::to_vec_pretty(config).map_err(|_| "无法序列化 sing-box 配置".to_owned())?;
        let temporary = self.config_path.with_extension("json.tmp");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temporary)
                .map_err(|_| "无法创建临时配置文件".to_owned())?;
            file.write_all(&data)
                .map_err(|_| "无法写入临时配置文件".to_owned())?;
            file.sync_all()
                .map_err(|_| "无法刷新临时配置文件".to_owned())?;
        }
        fs::rename(&temporary, &self.config_path)
            .map_err(|_| "无法替换本地 sing-box 配置文件".to_owned())
    }
}


#[cfg(windows)]
fn secure_config_directory(path: &Path) -> Result<(), String> {
    let username = std::env::var("USERNAME")
        .map_err(|_| "无法识别当前 Windows 用户，拒绝写入包含凭据的配置文件".to_owned())?;
    let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| ".".to_owned());
    let account = format!("{domain}\\{username}");
    let user_acl = format!("{account}:(OI)(CI)F");
    let output = Command::new("icacls.exe")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(user_acl)
        .arg("*S-1-5-18:(OI)(CI)F")
        .arg("*S-1-5-32-544:(OI)(CI)F")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "无法运行 icacls 设置本地配置目录权限".to_owned())?;
    if output.status.success() {
        Ok(())
    } else {
        Err("无法收紧本地配置目录 ACL，已阻止写入包含凭据的配置".to_owned())
    }
}

#[cfg(not(windows))]
fn secure_config_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

impl Drop for RuntimeManager {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        let _ = fs::remove_file(&self.config_path);
    }
}
