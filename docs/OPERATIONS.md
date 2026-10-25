# Windows operations

## First run

1. Open ProxyPilot, go to 代理节点, paste `hy2://` / `hysteria2://` links or a Base64 subscription body and import. UTF-8 text files are also supported. Maximum 10 nodes.
2. In 端口映射 select a node, set its Profile name and unique loopback port. Defaults are 18001–18010. Stop the core before editing.
3. In 设置 choose a trusted local sing-box.exe or download the official Windows x64 release. Downloads require the SHA-256 asset digest supplied by GitHub. An optional expected local EXE hash is checked before execution. SHA-256 is an integrity check, not a publisher signature.
4. Run sing-box check, then start. All listeners must become available. Only this application's child process is stopped.
5. In 诊断与验收 run egress/DNS tests. HTTPS IP services must return a plain-text IP. HTTP service failures and unclassified network timeouts do not prove node failure.

## Failure isolation

Select an enabled node while the core is running. Click the isolation action and confirm the interruption. The application tests all baselines first, temporarily changes only that outbound to a local unused UDP destination, tests every endpoint, then restores the original configuration and tests again. All listeners briefly restart. No firewall/system proxy rules are changed. A pass requires the selected endpoint to fail, all other endpoints to succeed, and recovery to succeed. Changing egress IP alone is not evidence of fallback: exit addresses can change legitimately.

## Browser acceptance

Use a separate browser profile for each SOCKS port. Enable SOCKS remote DNS explicitly (for browsers that support it), inspect the browser's DoH policy, and test DNS resolvers and WebRTC addresses with an appropriate public test service. Record service, time, profile, DoH/WebRTC settings and results. Compare against a direct baseline, and repeat after node failure. Browser DoH, system resolver behavior and WebRTC UDP are separate paths; a successful SOCKS hostname request does not establish browser leak freedom. Do not alter system settings automatically.

## Data, backup and removal

Data is stored under `%APPDATA%\alert0\ProxyPilot\config` (the exact directory follows `directories::ProjectDirs`). `nodes.json` is metadata, `settings.json` stores local settings/core path, `diagnostics.json` retains 500 diagnostic records, and `events.json` retains 500 structured events. `cores` retains each downloaded version with provenance. Runtime JSON is in `runtime/runtime.json` with a restricted directory ACL and is removed on normal stop/exit.

Metadata backup excludes passwords. Restore validates before replacing the list and saves `before-restore.json`. The original Windows user's Credential Manager entries remain usable; another machine/account must re-import original links. Re-importing a matching node repairs missing credentials without allocating a new port. Deleting a node removes its credentials. Do not assume a metadata backup is a password backup.

For rollback select the earlier retained core executable. Restart failure attempts to restore the previous in-memory working configuration. After an OS crash inspect `runtime/runtime.json`; it may contain credentials. With the app/core stopped, remove stale runtime files. To uninstall stop/exit, remove the portable folder, and optionally remove application data and the `ProxyPilot` entries in Windows Credential Manager. No registry startup entry, system proxy or firewall rule is installed.

## Build/package

Run `cargo fmt --all -- --check`, `cargo test --release --locked`, and `cargo clippy --release --locked --all-targets --all-features -- -D warnings`. Run `cargo run --release --example core_acceptance` to download/verify an official core and check 1/2/10 synthetic-node configs, port conflicts, listeners and cleanup. An existing core path may be passed after `--`.

Run `./scripts/package.ps1` to generate a portable ZIP with source and dependency license files. The downloaded sing-box is not bundled. Review the exact Slint/license terms and choose a project distribution license before public release; the generated inventory is not a licensing approval. Upgrade by stopping the old application and replacing the portable executable; keep a metadata backup.

For real protocol isolation acceptance without production credentials, generate a temporary self-signed `localhost` PEM certificate/key (do not add it to the system trust store), then run `cargo run --release --example loopback_acceptance -- <sing-box.exe> <cert.pem> <key.pem>`. This starts two local HY2 fixture inbounds, verifies native credential storage using a unique synthetic key, executes public HTTPS requests through both routes, injects one local outbound failure and restores it. The temporary self-signed TLS bypass is used only by the fixture. Diagnostic/lifecycle evidence is saved locally; it is distinct from remote production-node acceptance.
