slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let app = MainWindow::new()?;

    app.on_navigate(|page| {
        eprintln!("Navigation requested: {}", page);
    });

    app.on_action_requested({
        let app_weak = app.as_weak();
        move |action| {
            if let Some(app) = app_weak.upgrade() {
                let message = match action.as_str() {
                    "import" => "M0 演示：节点导入尚未接入，不会读取或保存真实节点。",
                    "start" => "M0 演示：尚未启动 sing-box。真实进程管理将在后续阶段实现。",
                    "test" => "M0 演示：尚未执行真实代理请求或出口 IP 检测。",
                    _ => "该功能将在对应开发阶段接入。",
                };
                app.set_status_message(message.into());
            }
        }
    });

    app.run()
}
