use crate::{config::generate_config, nodes::NodeStore};
use serde_json::Value;
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Stdio},
    time::{Duration, Instant},
};

pub struct RuntimeManager {
    core_path: Option<PathBuf>,
    config_path: PathBuf,
    child: Option<Child>,
    version: Option<String>,
    last_config: Option<Value>,
    core_hash: Option<String>,
    pub status: String,
}

impl RuntimeManager {
    pub fn new() -> Result<Self, String> {
        let dirs = directories::ProjectDirs::from("com", "alert0", "ProxyPilot")
            .ok_or_else(|| "无法确定应用数据目录".to_owned())?;
        Ok(Self::with_directory(dirs.config_dir().join("runtime")))
    }

    pub fn with_directory(directory: PathBuf) -> Self {
        Self {
            core_path: None,
            config_path: directory.join("runtime.json"),
            child: None,
            version: None,
            last_config: None,
            core_hash: None,
            status: "未启动".into(),
        }
    }

    pub fn core_path(&self) -> Option<&PathBuf> {
        self.core_path.as_ref()
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn is_running(&mut self) -> bool {
        let status = match self.child.as_mut() {
            Some(child) => child.try_wait(),
            None => return false,
        };
        match status {
            Ok(None) | Err(_) => true,
            Ok(Some(exit)) => {
                self.child = None;
                self.status = format!(
                    "核心已退出（{}）",
                    exit.code()
                        .map_or("无退出码".into(), |code| code.to_string())
                );
                crate::settings::log(&self.status);
                let _ = fs::remove_file(&self.config_path);
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
        if self.is_running() {
            return Err("请先停止核心再更换程序".into());
        }
        let mut command = crate::process::command(&path);
        command.arg("version");
        let output = crate::process::output(command, Duration::from_secs(10))
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
        self.core_hash = Some(crate::core::sha256(self.core_path.as_ref().unwrap())?);
        self.version = Some(version.clone());
        Ok(version)
    }

    pub fn check_only(&mut self, config: &Value) -> Result<(), String> {
        if self.is_running() {
            return Err("运行期间不能替换配置校验文件".into());
        }
        let result = self.validate_config(config);
        let _ = fs::remove_file(&self.config_path);
        result
    }

    fn validate_config(&self, config: &Value) -> Result<(), String> {
        let core = self
            .core_path
            .as_ref()
            .ok_or_else(|| "请先选择并验证 sing-box.exe".to_owned())?;
        crate::core::verify_hash(core, self.core_hash.as_deref().ok_or("核心尚未验证")?)?;
        self.write_config(config)?;
        let mut command = crate::process::command(core);
        command
            .arg("check")
            .arg("-c")
            .arg(&self.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let output = match crate::process::output(command, Duration::from_secs(15)) {
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
        let config = generate_config(store.nodes(), |id| store.secret_for(id))
            .map_err(|error| error.to_string())?;
        self.start_config(config)
    }

    pub fn start_config(&mut self, config: Value) -> Result<String, String> {
        if self.is_running() {
            return Ok("ProxyPilot 管理的 sing-box 进程已经在运行".to_owned());
        }
        crate::config::validate_route_isolation(&config).map_err(|e| e.to_string())?;
        let core = self
            .core_path
            .clone()
            .ok_or_else(|| "请先选择并验证 sing-box.exe".to_owned())?;
        crate::core::verify_hash(&core, self.core_hash.as_deref().ok_or("核心尚未验证")?)?;
        self.check_ports_available(&config)?;
        self.validate_config(&config)?;

        let child = match crate::process::command(core)
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
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(3) {
            if !self.is_running() {
                return Err("sing-box 启动后退出，未判定为成功".into());
            }
            if config["inbounds"].as_array().is_some_and(|inbounds| {
                inbounds.iter().all(|inbound| {
                    crate::diagnostics::listener_available(
                        inbound["listen_port"].as_u64().unwrap_or(0) as u16,
                    )
                })
            }) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !self.is_running() {
            return Err("sing-box 启动后立即退出；请检查核心版本与配置".to_owned());
        }
        if !config["inbounds"].as_array().is_some_and(|inbounds| {
            inbounds.iter().all(|inbound| {
                crate::diagnostics::listener_available(
                    inbound["listen_port"].as_u64().unwrap_or(0) as u16
                )
            })
        }) {
            let _ = self.stop();
            return Err("核心未能在 3 秒内开放所有入口，已停止".into());
        }
        self.last_config = Some(config.clone());
        self.status = "运行中".into();
        crate::settings::log("核心启动成功，所有本地入口已开放");
        Ok(format!(
            "sing-box 已启动；配置文件位于本地应用数据目录（{} 个入口）。",
            config["inbounds"].as_array().map_or(0, Vec::len)
        ))
    }

    pub fn stop(&mut self) -> Result<String, String> {
        let status = {
            let Some(child) = self.child.as_mut() else {
                let _ = fs::remove_file(&self.config_path);
                return Ok("当前没有由 ProxyPilot 启动的 sing-box 进程".to_owned());
            };
            child
                .try_wait()
                .map_err(|_| "无法检查 sing-box 进程状态；保留进程句柄以便重试".to_owned())?
        };
        if status.is_some() {
            self.child = None;
            let _ = fs::remove_file(&self.config_path);
            return Ok("sing-box 进程已经退出".to_owned());
        }

        let Some(mut child) = self.child.take() else {
            return Err("无法取得 ProxyPilot 的 sing-box 进程句柄".to_owned());
        };
        if child.kill().is_err() {
            self.child = Some(child);
            return Err(
                "无法停止 ProxyPilot 自己启动的 sing-box 进程；已保留进程句柄以便重试".to_owned(),
            );
        }
        if child.wait().is_err() {
            self.child = Some(child);
            return Err("等待 sing-box 退出失败；已保留进程句柄以便重试".to_owned());
        }
        let _ = fs::remove_file(&self.config_path);
        self.status = "已停止".into();
        crate::settings::log("应用管理的核心已停止");
        Ok("ProxyPilot 启动的 sing-box 进程已停止；其他进程未受影响".to_owned())
    }

    pub fn restart(&mut self, store: &NodeStore) -> Result<String, String> {
        let next =
            generate_config(store.nodes(), |id| store.secret_for(id)).map_err(|e| e.to_string())?;
        let previous = self.last_config.clone();
        self.stop()?;
        match self.start_config(next) {
            Ok(message) => Ok(message),
            Err(error) => {
                if let Some(previous) = previous {
                    let restored = self.start_config(previous).is_ok();
                    Err(format!(
                        "重启失败：{error}；上一配置恢复{}",
                        if restored {
                            "成功"
                        } else {
                            "失败，核心已停止"
                        }
                    ))
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Reversible, app-local failure injection; never touches firewall/system proxy.
    /// The UI obtains confirmation before entering this method.
    pub fn isolation_test(
        &mut self,
        id: &str,
        port: u16,
        settings: &crate::settings::Settings,
    ) -> Result<Vec<crate::diagnostics::DiagnosticRecord>, String> {
        if !self.is_running() {
            return Err("请先启动核心".into());
        }
        let original = self.last_config.clone().ok_or("缺少当前配置")?;
        let ports: Vec<u16> = original["inbounds"]
            .as_array()
            .ok_or("配置无入口")?
            .iter()
            .filter_map(|i| i["listen_port"].as_u64().map(|p| p as u16))
            .collect();
        let baseline = crate::diagnostics::batch(&ports, false, settings);
        if !baseline.iter().all(|r| r.success) {
            let details = baseline
                .iter()
                .filter(|r| !r.success)
                .map(|r| format!("端口 {}：{}", r.port, r.message))
                .collect::<Vec<_>>()
                .join("；");
            crate::diagnostics::append_history(&baseline)?;
            return Err(format!("基线测试并非全部成功，未执行故障注入。{details}"));
        }
        let mut fault = original.clone();
        let tag = format!("out-{id}");
        let outbound = fault["outbounds"]
            .as_array_mut()
            .and_then(|outbounds| outbounds.iter_mut().find(|o| o["tag"] == tag))
            .ok_or("所选节点不在运行配置中")?;
        // Keep the bound local UDP port open during the test so no real HY2 server
        // can receive this traffic. This affects only the selected outbound.
        let sink = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|_| "无法创建本地故障目标")?;
        outbound["server"] = serde_json::json!("127.0.0.1");
        outbound["server_port"] =
            serde_json::json!(sink.local_addr().map_err(|_| "无法获取故障端口")?.port());
        self.stop()?;
        let injected = self
            .start_config(fault)
            .map(|_| crate::diagnostics::batch(&ports, false, settings));
        let stopped = self.stop();
        let recovery = if stopped.is_ok() {
            self.start_config(original)
        } else {
            Err("停止故障配置失败".into())
        };
        if recovery.is_err() {
            return Err("故障测试后恢复失败，请停止核心并重新启动；未修改系统规则".into());
        }
        let mut results = baseline;
        for r in &mut results {
            r.kind = "isolation_baseline".into();
        }
        let mut during = injected?;
        let isolated = during.iter().all(|r| {
            if r.port == port {
                !r.success
            } else {
                r.success
            }
        });
        for r in &mut during {
            r.kind = "isolation_fault".into();
        }
        let mut after = crate::diagnostics::batch(&ports, false, settings);
        for r in &mut after {
            r.kind = "isolation_recovery".into();
        }
        let recovered = after.iter().all(|r| r.success);
        results.extend(during);
        results.extend(after);
        crate::diagnostics::append_history(&results)?;
        crate::settings::log(if isolated && recovered {
            "故障隔离实测通过，原配置已恢复"
        } else {
            "故障隔离结果未通过，原配置已恢复，请检查诊断记录"
        });
        Ok(results)
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
        crate::settings::write_json(&self.config_path, config)
    }
}

#[cfg(windows)]
fn secure_config_directory(path: &Path) -> Result<(), String> {
    let username = std::env::var("USERNAME")
        .map_err(|_| "无法识别当前 Windows 用户，拒绝写入包含凭据的配置文件".to_owned())?;
    let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| ".".to_owned());
    let account = format!("{domain}\\{username}");
    let user_acl = format!("{account}:(OI)(CI)F");
    let output = crate::process::command("icacls.exe")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(user_acl)
        .arg("*S-1-5-18:(OI)(CI)F")
        .arg("*S-1-5-32-544:(OI)(CI)F")
        .arg("/T")
        .arg("/C")
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
