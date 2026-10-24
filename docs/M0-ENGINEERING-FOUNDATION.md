# M0 工程骨架与 CI（Rust + Slint）

## 技术决策

- 桌面 UI：Slint 声明式 UI。
- 应用逻辑：Rust。
- 代理核心：独立的官方 sing-box 可执行文件；后续通过 Rust 的进程管理服务控制。
- 目标：Windows x64 桌面应用。
- 不引入 React、Node.js、Tauri 或 WebView。
- 保留 v2rayN，不修改其配置、进程或系统代理。
- 当前 UI 中的节点和端口为静态演示数据，不代表真实监听或测试结果。

## 本阶段交付

- Cargo 工程与 Slint 编译入口。
- 初始桌面窗口及中文导航。
- 统一的 Rust 事件回调示例。
- Windows GitHub Actions：格式检查、编译检查、测试、Clippy。
- 忽略本地构建产物、日志及包含凭据的运行配置。
- 可复现的本地开发和验收命令。

## 本地开发环境

1. 安装 Rust stable 工具链和 Cargo。
2. 安装 Windows 所需的 C++ Build Tools / MSVC 工具链及 Windows SDK（具体要求以 Slint 当前官方构建文档为准）。
3. 克隆仓库。
4. 在仓库根目录执行：

```powershell
cargo fmt --all -- --check
cargo check
cargo test
cargo run
```

首次构建需要从 crates.io 下载 Rust 依赖。构建结果应以实际命令输出为准。

## 验收标准

- Slint UI 在编译期生成 Rust 绑定。
- `cargo check` 成功完成。
- `cargo test` 成功完成。
- `cargo fmt --all -- --check` 通过。
- 点击“导入节点”“测试连接”“启动核心”只显示明确的未接入提示，不会伪造真实操作成功。
- UI 明确标注静态示例数据。
- Git 仓库不包含真实 HY2 分享链接、密码、生产配置或本机日志。
- GitHub Actions 的检查必须真实执行；任何步骤失败都应让 CI 失败，不得用 continue-on-error 隐藏失败。

## 下一阶段

M0 通过后进入 M1：实现 HY2 分享链接解析、字段掩码、错误分类和单元测试；在此之前不启动真实代理核心。
