# ProxyPilot

**ProxyPilot Desktop** is a Windows desktop manager for local proxy endpoints and sing-box, designed for explicit per-profile routing.

> One Profile. One Port. One Route.

## Goals

- Import and manage Hysteria 2 (HY2) share links locally.
- Generate and validate sing-box configuration.
- Map each local SOCKS5 endpoint to exactly one configured outbound.
- Start, stop, and inspect the sing-box process from a Windows desktop UI.
- Test connectivity and record observed egress IP per endpoint.
- Provide DNS-path checks and controlled failure-isolation tests.
- Coexist with an existing v2rayN installation without replacing it.

## Initial scope

- Windows x64 desktop application.
- Rust + Slint native desktop UI and application logic; no React, Node.js, Tauri, or WebView.
- sing-box as a separately managed core process.
- First milestone: 10 HY2 nodes and 10 loopback-only SOCKS5 endpoints.
- Suggested default ports: 18001–18010; configurable with collision checks.
- Explicit routing only; no automatic failover or load balancing in the first release.

## Non-goals for the first release

- No new proxy protocol implementation.
- No replacement for v2rayN.
- No system-wide TUN/VPN mode.
- No claim that a successful IP test alone proves DNS or WebRTC leak-free behavior.
- No remote/cloud synchronization of proxy credentials.

## Design documents

- [Product and architecture](docs/PRODUCT-ARCHITECTURE.md)
- [M0 engineering foundation](docs/M0-ENGINEERING-FOUNDATION.md)
- [Implementation plan](docs/IMPLEMENTATION-PLAN.md)
- [Development roadmap and acceptance](docs/ROADMAP-ACCEPTANCE.md)
- [Security and operations](docs/SECURITY-OPERATIONS.md)

## Run locally

Install the stable Rust toolchain and Windows build prerequisites, then run:

```powershell
cargo run
```

- Paste one `hy2://` / `hysteria2://` link per line, or a standard / URL-safe Base64 list.
- Manage imported nodes: rename, enable/disable, delete, and detect duplicates.
- Node metadata is stored locally; passwords and obfuscation secrets use Windows Credential Manager.
- Choose an existing `sing-box.exe` with the native file picker. ProxyPilot checks its version, generates configuration in memory, checks local port conflicts, runs `sing-box check`, then starts only the child process it created.
- “测试出口 IP” and “DNS 路径诊断” run asynchronously using Windows `curl.exe`.

Version 0.2.0 adds working navigation, editable ports/Profiles, background lifecycle operations, persisted settings, diagnostic history/export, metadata backup/restore, and confirmed app-local failure isolation. The official Windows x64 core downloader checks GitHub's SHA-256 asset digest; local EXEs can be checked against a trusted expected hash. Prior core versions remain available for rollback. SHA-256 integrity is not a publisher signature.

See [Windows operations](docs/OPERATIONS.md), [acceptance evidence](docs/ACCEPTANCE.md) and [changelog](CHANGELOG.md). Build a local portable ZIP with `./scripts/package.ps1`. Browser DNS/DoH/WebRTC inspection is a documented manual workflow; live network and clean-machine acceptance remain separate from source checks.

## Safety and privacy

HY2 links are credentials. Do not commit real links or generated production configs. SOCKS listeners bind to `127.0.0.1`; no system proxy, TUN, firewall, or v2rayN settings are changed. Node secrets are stored through Windows Credential Manager. While sing-box is running, its runtime JSON necessarily contains plaintext credentials; ProxyPilot restricts the app data directory ACL and removes the file on normal stop/exit. A forced process termination or system crash can leave that file behind, so inspect and remove it manually if ProxyPilot did not exit cleanly.

## Development status

The Windows v0.2.0 workflows are implemented and validated locally with automated tests and official-core synthetic acceptance. No remote CI result, live-node connectivity, browser leak result, clean-machine installation, or public distribution licensing review is inferred from those checks. See `docs/ACCEPTANCE.md` for evidence and remaining environment acceptance.
