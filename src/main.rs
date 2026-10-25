#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use proxypilot::{
    config::generate_config,
    core, diagnostics,
    nodes::NodeStore,
    runtime::RuntimeManager,
    settings::{self, Settings},
};
use slint::{ModelRc, SharedString, VecModel};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
slint::include_modules!();
struct State {
    store: NodeStore,
    runtime: RuntimeManager,
    settings: Settings,
}
type SharedState = Arc<Mutex<State>>;
fn model(rows: Vec<String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        rows.into_iter().map(SharedString::from).collect::<Vec<_>>(),
    ))
}
fn refresh(app: &MainWindow, state: &mut State) {
    let running = state.runtime.is_running();
    app.set_core_running(running);
    app.set_runtime_status(state.runtime.status.clone().into());
    app.set_core_path(
        state
            .runtime
            .core_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "尚未选择核心".into())
            .into(),
    );
    app.set_core_version(state.runtime.version().unwrap_or("未验证").into());
    app.set_node_count_text(state.store.nodes().len().to_string().into());
    app.set_node_rows(model(
        state
            .store
            .nodes()
            .iter()
            .map(|n| {
                format!(
                    "{} · {} · {} · 127.0.0.1:{} → {}:{} · SNI {} · TLS {} · 混淆 {}{} · 监听 {}",
                    if n.enabled { "启用" } else { "停用" },
                    n.name,
                    n.profile_name,
                    n.listen_port,
                    n.server,
                    n.server_port,
                    n.sni.as_deref().unwrap_or("默认"),
                    if n.insecure {
                        "跳过证书校验"
                    } else {
                        "校验证书"
                    },
                    n.obfs_type.as_deref().unwrap_or("无"),
                    if n.warnings.is_empty() {
                        ""
                    } else {
                        " · 参数待检查，禁止启动"
                    },
                    if running && n.enabled {
                        if diagnostics::listener_available(n.listen_port) {
                            "可用"
                        } else {
                            "不可用"
                        }
                    } else {
                        "未启动"
                    }
                )
            })
            .collect(),
    ));
    let history = diagnostics::read_history().unwrap_or_default();
    let mut latest = std::collections::HashMap::new();
    for row in &history {
        if row.kind == "egress_ip" {
            latest.insert(row.port, row);
        }
    }
    latest.retain(|port, _| {
        state
            .store
            .nodes()
            .iter()
            .any(|n| n.enabled && n.listen_port == *port)
    });
    app.set_success_count(
        latest
            .values()
            .filter(|r| r.success)
            .count()
            .to_string()
            .into(),
    );
    app.set_failure_count(
        latest
            .values()
            .filter(|r| !r.success)
            .count()
            .to_string()
            .into(),
    );
    app.set_diagnostic_rows(model(
        history
            .iter()
            .rev()
            .take(100)
            .map(|r| {
                format!(
                    "{} · {} · 端口 {} · {} · {} ms · {} {} · 服务 {}",
                    r.checked_at_unix,
                    r.kind,
                    r.port,
                    if r.success { "成功" } else { "失败" },
                    r.elapsed_ms,
                    r.egress_ip.as_deref().unwrap_or(""),
                    r.message,
                    r.service.as_deref().unwrap_or("历史记录未标记")
                )
            })
            .collect(),
    ));
    app.set_log_rows(model(
        settings::read_logs()
            .iter()
            .rev()
            .map(|r| format!("{} · {}", r.at, r.event))
            .collect(),
    ));
}
fn work(
    app: &MainWindow,
    state: &SharedState,
    action: impl FnOnce(&mut State) -> Result<String, String> + Send + 'static,
) {
    if app.get_busy() {
        return;
    }
    app.set_busy(true);
    app.set_status_message("正在处理…".into());
    let state = Arc::clone(state);
    let weak = app.as_weak();
    std::thread::spawn(move || {
        let result = match state.lock() {
            Ok(mut state) => action(&mut state),
            Err(_) => Err("应用状态不可用，请重启".into()),
        };
        let success = result.is_ok();
        let message = result.unwrap_or_else(|e| e);
        settings::log(if success {
            "操作完成"
        } else {
            "操作失败，请查看界面错误信息"
        });
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(app) = weak.upgrade() {
                app.set_busy(false);
                app.set_status_message(message.into());
                if let Ok(mut state) = state.lock() {
                    refresh(&app, &mut state);
                }
            }
        });
    });
}
fn selected(state: &State, index: i32) -> Result<proxypilot::nodes::NodeRecord, String> {
    usize::try_from(index)
        .ok()
        .and_then(|i| state.store.nodes().get(i))
        .cloned()
        .ok_or_else(|| "请先选择一个节点".into())
}
fn stopped(state: &mut State) -> Result<(), String> {
    if state.runtime.is_running() {
        Err("请先停止核心再修改节点、映射或恢复备份".into())
    } else {
        Ok(())
    }
}
fn confirm(title: &str, description: &str) -> bool {
    rfd::MessageDialog::new()
        .set_title(title)
        .set_description(description)
        .set_buttons(rfd::MessageButtons::YesNo)
        .show()
        == rfd::MessageDialogResult::Yes
}
fn main() -> Result<(), slint::PlatformError> {
    let _instance_lock = match settings::instance_lock() {
        Ok(lock) => lock,
        Err(error) => {
            rfd::MessageDialog::new()
                .set_title("ProxyPilot")
                .set_description(error)
                .show();
            return Ok(());
        }
    };
    let app = MainWindow::new()?;
    let initial = (|| -> Result<State, String> {
        let settings = Settings::load()?;
        let store = NodeStore::open_default()?;
        let mut runtime = RuntimeManager::new()?;
        if let Some(path) = &settings.core_path {
            let verified = settings
                .core_sha256
                .as_deref()
                .map(|hash| core::verify_hash(path, hash).map(|_| ()))
                .unwrap_or(Ok(()));
            if let Err(error) = verified.and_then(|_| runtime.choose_core(path.clone()).map(|_| ()))
            {
                runtime.status = error;
            }
        }
        Ok(State {
            store,
            runtime,
            settings,
        })
    })();
    let mut initial = match initial {
        Ok(s) => s,
        Err(error) => {
            rfd::MessageDialog::new()
                .set_title("初始化失败")
                .set_description(error)
                .show();
            return Ok(());
        }
    };
    app.set_ip_url(initial.settings.ip_url.clone().into());
    app.set_dns_url(initial.settings.dns_url.clone().into());
    app.set_concurrency(initial.settings.concurrency.to_string().into());
    app.set_timeout_seconds(initial.settings.timeout_seconds.to_string().into());
    refresh(&app, &mut initial);
    let state = Arc::new(Mutex::new(initial));
    settings::log("ProxyPilot 启动");
    app.on_navigate({
        let weak = app.as_weak();
        move |page| {
            if let Some(app) = weak.upgrade() {
                app.set_current_page(page);
            }
        }
    });
    app.on_select_node({
        let weak = app.as_weak();
        let state = Arc::clone(&state);
        move |index| {
            if let (Some(app), Ok(state)) = (weak.upgrade(), state.try_lock()) {
                if let Ok(node) = selected(&state, index) {
                    app.set_selected_node(index);
                    app.set_rename_input(node.name.into());
                    app.set_profile_input(node.profile_name.into());
                    app.set_port_input(node.listen_port.to_string().into());
                }
            }
        }
    });
    app.on_import_links({
        let weak = app.as_weak();
        let state = Arc::clone(&state);
        move |text| {
            if let Some(app) = weak.upgrade() {
                let text = text.to_string();
                work(&app, &state, move |state| {
                    stopped(state)?;
                    if text.len() > 1_048_576 {
                        return Err("导入内容超过 1 MiB".into());
                    }
                    let result = state.store.import_text(&text);
                    Ok(format!(
                        "新增 {}，重复 {}，警告 {}{}\n{}",
                        result.added.len(),
                        result.duplicates,
                        result.warning_count,
                        if result.limit_reached {
                            "，已达 10 节点上限"
                        } else {
                            ""
                        },
                        result.errors.join("\n")
                    ))
                });
                app.set_link_input("".into());
            }
        }
    });
    app.on_choose_import_file({
        let weak = app.as_weak();
        move || {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("UTF-8 文本", &["txt"])
                .pick_file()
            {
                let result = std::fs::metadata(&path)
                    .map_err(|_| "无法读取文件")
                    .and_then(|m| {
                        if m.len() > 1_048_576 {
                            Err("文件超过 1 MiB")
                        } else {
                            Ok(())
                        }
                    })
                    .and_then(|_| std::fs::read_to_string(path).map_err(|_| "文件不是有效 UTF-8"));
                if let Some(app) = weak.upgrade() {
                    match result {
                        Ok(text) => app.set_link_input(text.into()),
                        Err(e) => app.set_status_message(e.into()),
                    }
                }
            }
        }
    });
    app.on_rename_node({
        let weak = app.as_weak();
        let state = Arc::clone(&state);
        move |index, name| {
            if let Some(app) = weak.upgrade() {
                let name = name.to_string();
                work(&app, &state, move |state| {
                    stopped(state)?;
                    let node = selected(state, index)?;
                    state.store.rename(&node.id, &name)?;
                    Ok("名称已保存".into())
                });
            }
        }
    });
    app.on_save_mapping({
        let weak = app.as_weak();
        let state = Arc::clone(&state);
        move |index, profile, port| {
            if let Some(app) = weak.upgrade() {
                let profile = profile.to_string();
                let port = port.to_string();
                work(&app, &state, move |state| {
                    stopped(state)?;
                    let node = selected(state, index)?;
                    let port = port.trim().parse::<u16>().map_err(|_| "端口须为 1–65535")?;
                    state.store.set_mapping(&node.id, &profile, port)?;
                    Ok("Profile 与监听端口已保存".into())
                });
            }
        }
    });
    app.on_node_action({
        let weak = app.as_weak();
        let state = Arc::clone(&state);
        move |index, action| {
            if let Some(app) = weak.upgrade() {
                if action == "delete" && !confirm("删除节点", "删除所选节点及其本地凭据？")
                {
                    return;
                }
                let action = action.to_string();
                work(&app, &state, move |state| {
                    stopped(state)?;
                    let node = selected(state, index)?;
                    match action.as_str() {
                        "delete" => state.store.delete(&node.id)?,
                        "toggle" => state.store.set_enabled(&node.id, !node.enabled)?,
                        _ => return Err("不支持的操作".into()),
                    }
                    Ok("节点已更新".into())
                });
                app.set_selected_node(-1);
            }
        }
    });
    app.on_choose_core({
        let weak = app.as_weak();
        let state = Arc::clone(&state);
        move || {
            let Some(path) = rfd::FileDialog::new()
                .add_filter("sing-box", &["exe"])
                .pick_file()
            else {
                return;
            };
            if let Some(app) = weak.upgrade() {
                let expected = app.get_expected_hash().to_string();
                work(&app, &state, move |state| {
                    select_core(state, path, &expected)
                });
            }
        }
    });
    app.on_save_settings({
        let weak = app.as_weak();
        let state = Arc::clone(&state);
        move |ip, dns, concurrency, timeout| {
            if let Some(app) = weak.upgrade() {
                work(&app, &state, move |state| {
                    let next = Settings {
                        core_path: state.settings.core_path.clone(),
                        core_sha256: state.settings.core_sha256.clone(),
                        ip_url: ip.to_string(),
                        dns_url: dns.to_string(),
                        concurrency: concurrency.parse().map_err(|_| "并发数无效")?,
                        timeout_seconds: timeout.parse().map_err(|_| "超时无效")?,
                    };
                    next.save()?;
                    state.settings = next;
                    Ok("设置已保存".into())
                });
            }
        }
    });
    app.on_action_requested({ let weak = app.as_weak(); let state = Arc::clone(&state); move |action| {
        let Some(app) = weak.upgrade() else { return; }; let index = app.get_selected_node();
        let path = match action.as_str() {
            "backup" | "export" => rfd::FileDialog::new().add_filter("JSON", &["json"]).set_file_name(if action == "backup" { "ProxyPilot-metadata.json" } else { "ProxyPilot-diagnostics.json" }).save_file(),
            "restore" => { if !confirm("恢复节点清单", "恢复会替换节点元数据，并先备份当前清单。备份不包含密码；跨电脑恢复后须重新导入链接。继续？") { return; } rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file() },
            "isolation" => { if !confirm("故障隔离测试", "将测试基线，重启应用管理的核心，把所选出站临时指向本机无服务端口，测试其他出站，最后恢复原配置。所有入口会短暂中断。不修改防火墙或系统代理。继续？") { return; } None },
            _ => None,
        };
        if matches!(action.as_str(),"backup"|"restore"|"export") && path.is_none() { return; }
        let action = action.to_string(); work(&app,&state,move |state| match action.as_str() {
            "start" => state.runtime.start(&state.store), "stop" => state.runtime.stop(), "restart" => state.runtime.restart(&state.store),
            "config" | "check" => {
                let config = generate_config(state.store.nodes(),|id| state.store.secret_for(id)).map_err(|e| e.to_string())?;
                if action == "check" { stopped(state)?; state.runtime.check_only(&config)?; }
                Ok(format!("{}：{} 个入口、{} 个出站，一对一显式路由校验通过", if action == "check" { "sing-box check 通过" } else { "内存配置预览" }, config["inbounds"].as_array().map_or(0,Vec::len), config["outbounds"].as_array().map_or(0,Vec::len)))
            }
            "download" => { stopped(state)?; let path = core::download_official()?; select_core(state,path,"") },
            "test" | "dns" => {
                if !state.runtime.is_running() { return Err("请先启动核心，避免误测其他程序的端口".into()); }
                let ports: Vec<_> = state.store.nodes().iter().filter(|n| n.enabled).map(|n| n.listen_port).collect();
                let results = diagnostics::batch(&ports,action == "dns",&state.settings); diagnostics::append_history(&results)?;
                Ok(format!("诊断完成：{} / {} 成功，详情见诊断页面", results.iter().filter(|r| r.success).count(), results.len()))
            }
            "isolation" => { let node = selected(state,index)?; let results = state.runtime.isolation_test(&node.id,node.listen_port,&state.settings)?;
                let passed = results.iter().filter(|r| r.kind == "isolation_fault").all(|r| if r.port == node.listen_port { !r.success } else { r.success }) && results.iter().filter(|r| r.kind == "isolation_recovery").all(|r| r.success);
                Ok(format!("故障隔离{}，原配置已恢复。详情见诊断记录。",if passed { "通过" } else { "未通过" }))
            }
            "backup" => { state.store.backup(&path.unwrap())?; Ok("元数据备份完成，不包含密码。".into()) },
            "restore" => { stopped(state)?; state.store.backup(&settings::data_dir()?.join("before-restore.json"))?; state.store.restore(&path.unwrap())?; Ok("元数据已恢复，缺少本机凭据时请重新导入链接。".into()) },
            "export" => { settings::write_json(&path.unwrap(),&diagnostics::read_history()?)?; Ok("诊断报告已导出，包含端口和出口 IP，不含分享链接或凭据。".into()) },
            "refresh" => Ok("状态与历史已刷新".into()), _ => Err("未知操作".into()),
        });
    }});
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_secs(2),
        {
            let weak = app.as_weak();
            let state = Arc::clone(&state);
            move || {
                if let (Some(app), Ok(mut state)) = (weak.upgrade(), state.try_lock()) {
                    if !app.get_busy() {
                        refresh(&app, &mut state);
                    }
                }
            }
        },
    );
    app.window().on_close_requested({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                if app.get_busy() {
                    app.set_status_message(
                        "正在执行操作，请等待完成后关闭，以便清理核心与临时配置。".into(),
                    );
                    return slint::CloseRequestResponse::KeepWindowShown;
                }
            }
            slint::CloseRequestResponse::HideWindow
        }
    });
    app.run()
}
fn select_core(state: &mut State, path: PathBuf, expected: &str) -> Result<String, String> {
    if !expected.trim().is_empty() {
        core::verify_hash(&path, expected.trim())?;
    }
    let version = state.runtime.choose_core(path.clone())?;
    let hash = core::sha256(&path)?;
    state.settings.core_path = Some(path);
    state.settings.core_sha256 = Some(hash.clone());
    state.settings.save()?;
    Ok(format!("核心已选择：{version}\nSHA-256: {hash}"))
}
