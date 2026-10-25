use proxypilot::nodes::{decode_import_text, parse_hy2_link};

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let app = MainWindow::new()?;

    app.on_navigate(|page| {
        eprintln!("Navigation requested: {}", page);
    });

    app.on_import_links({
        let app_weak = app.as_weak();
        move |links| {
            let links = match decode_import_text(links.as_str()) {
                Ok(text) => text,
                Err(error) => {
                    if let Some(app) = app_weak.upgrade() {
                        app.set_status_message(error.to_string().into());
                    }
                    return;
                }
            };
            let mut imported = Vec::new();
            let mut failed = Vec::new();

            for (index, line) in links.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                match parse_hy2_link(line) {
                    Ok(node) => {
                        let mut summary =
                            format!("{} — {}:{}", node.name, node.server, node.server_port);
                        if !node.warnings.is_empty() {
                            let names = node
                                .warnings
                                .iter()
                                .map(|warning| warning.parameter.as_str())
                                .collect::<Vec<_>>()
                                .join(", ");
                            summary.push_str(&format!("（需检查参数：{}）", names));
                        }
                        imported.push(summary);
                    }
                    Err(error) => failed.push(format!("第 {} 行：{}", index + 1, error)),
                }
            }

            let mut message = format!(
                "解析完成：成功 {} 条，失败 {} 条。",
                imported.len(),
                failed.len()
            );
            if !imported.is_empty() {
                message.push_str("\n成功：");
                message.push_str(&imported.join("；"));
            }
            if !failed.is_empty() {
                message.push_str("\n失败：");
                message.push_str(&failed.join("；"));
            }

            if let Some(app) = app_weak.upgrade() {
                app.set_status_message(message.into());
            }
        }
    });

    app.on_action_requested({
        let app_weak = app.as_weak();
        move |action| {
            if let Some(app) = app_weak.upgrade() {
                let message = match action.as_str() {
                    "import" => "请粘贴 HY2 分享链接（每行一条）或 Base64 编码的链接列表，再点击“解析并预览”。",
                    "start" => "当前尚未启动 sing-box。真实进程管理将在后续阶段实现。",
                    "test" => "当前尚未执行真实代理请求或出口 IP 检测。",
                    _ => "该功能将在对应开发阶段接入。",
                };
                app.set_status_message(message.into());
            }
        }
    });

    app.run()
}
