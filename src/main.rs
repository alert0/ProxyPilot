use proxypilot::{config::generate_config, nodes::NodeStore};
use std::{cell::RefCell, rc::Rc};
use slint::{ModelRc, SharedString, VecModel};

slint::include_modules!();

fn refresh_node_rows(app: &MainWindow, store: &Option<NodeStore>) {
    let rows: Vec<SharedString> = store
        .as_ref()
        .map(|store| {
            store
                .nodes()
                .iter()
                .map(|node| {
                    let state = if node.enabled { "启用" } else { "停用" };
                    format!(
                        "{state}  ·  {}  ·  {}:{}{}",
                        node.name,
                        node.server,
                        node.server_port,
                        node.sni
                            .as_ref()
                            .map(|sni| format!("  ·  SNI {sni}"))
                            .unwrap_or_default()
                    )
                    .into()
                })
                .collect()
        })
        .unwrap_or_default();
    app.set_node_count_text(rows.len().to_string().into());
    app.set_node_rows(ModelRc::new(VecModel::from(rows)));
}

fn main() -> Result<(), slint::PlatformError> {
    let app = MainWindow::new()?;
    let store = Rc::new(RefCell::new(NodeStore::open_default().ok()));

    if store.borrow().is_none() {
        app.set_status_message(
            "本地节点存储初始化失败。请检查 Windows 用户配置目录与凭据管理器权限。"
                .into(),
        );
    } else {
        refresh_node_rows(&app, &store.borrow());
    }

    app.on_navigate(|page| {
        let _ = page;
    });

    app.on_import_links({
        let app_weak = app.as_weak();
        let store = Rc::clone(&store);
        move |input| {
            let summary = {
                let mut guard = store.borrow_mut();
                match guard.as_mut() {
                    Some(store) => Some(store.import_text(input.as_str())),
                    None => None,
                }
            };

            let Some(summary) = summary else {
                if let Some(app) = app_weak.upgrade() {
                    app.set_status_message(
                        "本地节点存储不可用，无法导入。请检查应用数据目录与 Windows 凭据管理器。"
                            .into(),
                    );
                }
                return;
            };

            let mut message = format!(
                "导入完成：新增 {}，重复 {}，警告 {}。",
                summary.added.len(),
                summary.duplicates,
                summary.warning_count
            );
            if summary.limit_reached {
                message.push_str(" 已达到最多 10 个节点的限制。");
            }
            if !summary.errors.is_empty() {
                message.push_str(" 错误：");
                message.push_str(&summary.errors.join("；"));
            }
            if let Some(app) = app_weak.upgrade() {
                app.set_status_message(message.into());
                refresh_node_rows(&app, &store.borrow());
            }
        }
    });

    app.on_select_node({
        let app_weak = app.as_weak();
        let store = Rc::clone(&store);
        move |index| {
            if index < 0 {
                return;
            }
            let name = store
                .borrow()
                .as_ref()
                .and_then(|store| store.nodes().get(index as usize))
                .map(|node| node.name.clone());
            if let (Some(app), Some(name)) = (app_weak.upgrade(), name) {
                app.set_selected_node(index);
                app.set_rename_input(name.into());
                app.set_status_message("已选择节点。重命名只修改本地显示名称。".into());
            }
        }
    });

    app.on_rename_node({
        let app_weak = app.as_weak();
        let store = Rc::clone(&store);
        move |index, name| {
            if index < 0 {
                return;
            }
            let result = {
                let mut guard = store.borrow_mut();
                match guard.as_mut() {
                    Some(store) => store
                        .nodes()
                        .get(index as usize)
                        .map(|node| node.id.clone())
                        .ok_or_else(|| "找不到所选节点".to_owned())
                        .and_then(|id| store.rename(&id, name.as_str())),
                    None => Err("本地节点存储不可用".to_owned()),
                }
            };
            if let Some(app) = app_weak.upgrade() {
                match result {
                    Ok(()) => app.set_status_message("节点名称已保存。".into()),
                    Err(error) => app.set_status_message(error.into()),
                }
                refresh_node_rows(&app, &store.borrow());
            }
        }
    });

    app.on_node_action({
        let app_weak = app.as_weak();
        let store = Rc::clone(&store);
        move |index, action| {
            if index < 0 {
                return;
            }
            let result = {
                let mut guard = store.borrow_mut();
                match guard.as_mut() {
                    Some(store) => {
                        let selected = store.nodes().get(index as usize).cloned();
                        match selected {
                            None => Err("找不到所选节点".to_owned()),
                            Some(node) if action == "toggle" => {
                                store.set_enabled(&node.id, !node.enabled)
                            }
                            Some(node) if action == "delete" => store.delete(&node.id),
                            _ => Err("不支持的节点操作".to_owned()),
                        }
                    }
                    None => Err("本地节点存储不可用".to_owned()),
                }
            };
            if let Some(app) = app_weak.upgrade() {
                match result {
                    Ok(()) => {
                        app.set_status_message(
                            if action == "delete" {
                                "节点已删除；本地凭据也已请求删除。".into()
                            } else {
                                "节点启用状态已更新。".into()
                            },
                        );
                        if action == "delete" {
                            app.set_selected_node(-1);
                            app.set_rename_input("".into());
                        }
                    }
                    Err(error) => app.set_status_message(error.into()),
                }
                refresh_node_rows(&app, &store.borrow());
            }
        }
    });

    app.on_action_requested({
        let app_weak = app.as_weak();
        let store = Rc::clone(&store);
        move |action| {
            let message = match action.as_str() {
                "import" => "粘贴 HY2 分享链接（每行一条）或 Base64 链接列表，再点击“解析并预览”。".to_owned(),
                "config" => {
                    let guard = store.borrow();
                    match guard.as_ref() {
                        Some(store) => match generate_config(store.nodes(), |id| store.secret_for(id)) {
                            Ok(config) => format!(
                                "配置预览成功：{} 个 SOCKS5 入口、{} 个 HY2 出站、{} 条显式路由。尚未调用 sing-box check，也未启动核心。",
                                config["inbounds"].as_array().map_or(0, Vec::len),
                                config["outbounds"].as_array().map_or(0, Vec::len),
                                config["route"]["rules"].as_array().map_or(0, Vec::len)
                            ),
                            Err(error) => format!("无法生成配置预览：{error}"),
                        },
                        None => "本地节点存储不可用，无法生成配置预览。".to_owned(),
                    }
                }
                "start" => "配置预览已接入；sing-box 版本检测、配置文件保护、核心启动/停止将在下一阶段实现。当前不会启动代理。".to_owned(),
                "test" => "尚未执行真实代理请求。出口 IP、DNS 与故障隔离测试将在核心生命周期完成后接入。".to_owned(),
                _ => "该功能将在对应开发阶段接入。".to_owned(),
            };
            if let Some(app) = app_weak.upgrade() {
                app.set_status_message(message.into());
            }
        }
    });

    app.run()
}
