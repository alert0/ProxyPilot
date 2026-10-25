# ProxyPilot 开发路线图与验收标准

> 历史初始路线图。实现现已采用 Rust + Slint（没有 Tauri/React）。当前功能与验收状态见 [OPERATIONS](OPERATIONS.md) 和 [ACCEPTANCE](ACCEPTANCE.md)。

- 状态：Initial plan
- 原则：每阶段可独立验收；先验证核心能力，再扩大 UI 和打包范围。
- 首版基线：Windows x64、10 个 HY2 节点、10 个本地 SOCKS5 入口。

## Phase 0 — Repository and engineering foundation

### Work
- Establish Rust/Tauri + React/TypeScript project.
- Define formatting, linting, type-checking, unit-test, and CI commands.
- Add architecture docs, issue templates, and security guidance.
- Add a mock-data UI that does not claim to control real proxies.

### Acceptance
- Fresh clone can install dependencies and run documented checks.
- CI checks formatting/lint/typecheck/tests on pull requests.
- No real credentials, share links, generated runtime configs, or local logs in Git.
- UI clearly labels mock data as demo data.

## Phase 1 — Node import and config generation

### Work
- Paste multiple HY2 links or import a text file, one link per line.
- Parse valid links without logging secrets.
- Show a masked preview and per-line validation status.
- Store node metadata and protected credentials locally.
- Generate 1-, 2-, and 10-node configs from typed data.
- Detect duplicate nodes, malformed links, unsupported parameters, and port conflicts.
- Validate generated config with the selected sing-box binary.

### Acceptance
- Valid supported HY2 links parse to the correct host, port, password, SNI, and supported obfuscation parameters.
- Malformed or unsupported links are reported without exposing the raw link.
- Unknown security-relevant parameters cause a warning or block launch; they are not silently ignored.
- Generated tags are unique and every configured endpoint has exactly one explicit target outbound.
- Ports are unique and listeners bind to 127.0.0.1 by default.
- Config checker failure blocks startup and shows a sanitized actionable error.
- Unit tests cover URI encoding, IPv4/IPv6 host syntax where supported, percent-encoded credentials, missing fields, duplicates, and obfuscation variants.

## Phase 2 — sing-box lifecycle and local endpoints

### Work
- Download/select the official sing-box executable and show version/checksum status.
- Start, stop, restart, and monitor the exact child process.
- Check ports before launch and identify conflicts.
- Show endpoint listener status independently of remote connectivity.
- Preserve v2rayN settings and processes.

### Acceptance
- App starts the configured sing-box executable with an argument array and no shell interpolation.
- App only stops its own child process.
- A conflicting port prevents startup and does not kill the conflicting process.
- Stopping ProxyPilot does not terminate v2rayN or unrelated sing-box processes.
- No system proxy or TUN setting is changed in v1.
- Unexpected core exit is reflected in the UI and sanitized logs.

## Phase 3 — Connectivity and egress verification

### Work
- Test each local SOCKS endpoint through a configurable HTTPS IP-echo service.
- Capture exit code, elapsed time, returned IP, timestamp, and sanitized error.
- Add batch testing with bounded concurrency.
- Keep last-known results visibly timestamped.

### Acceptance
- Each endpoint is tested through its own local port.
- A failed request cannot be displayed as a successful test.
- Non-zero process exit codes and stderr are captured correctly.
- Results show “last checked at” and do not imply current availability indefinitely.
- Different endpoints are not required to have different IPs; shared exits can be legitimate. The acceptance check is that each route matches its configured node's observed exit.
- If the test service is unavailable, report “test service error” rather than “proxy failed” unless the evidence supports that conclusion.

## Phase 4 — DNS diagnostics and failure isolation

### Work
- Provide DNS test guidance and optional checks through documented test services.
- Show limitations around browser DoH, system DNS, and WebRTC.
- Provide a controlled node-isolation workflow with confirmation and recovery.
- Re-test all unaffected endpoints after a single node failure.

### Acceptance
- Report distinguishes SOCKS remote DNS request from browser/system DNS behavior.
- No “leak-free” guarantee based solely on an external web test.
- Blocking one test node causes its assigned endpoint to fail, without silently routing it through another node.
- Other configured endpoints remain usable during the isolated node failure, subject to their own network health.
- Recovery restores the expected endpoint mapping and test behavior.
- Test instructions include cleanup/restore steps and never permanently alter firewall rules without explicit confirmation.

## Phase 5 — Packaging and release candidate

### Work
- Build a Windows x64 installer or portable package.
- Include version metadata and third-party notices.
- Document sing-box binary acquisition, integrity verification, and updates.
- Add backup/restore for app metadata and config templates, excluding plaintext secrets by default.

### Acceptance
- Clean Windows environment can install, launch, import sample links, validate config, and uninstall.
- Existing v2rayN installation remains functional.
- App data and generated configs have appropriately restrictive Windows ACLs.
- Logs and exported reports contain no credentials.
- Release notes list tested Windows versions, sing-box version, known limitations, and third-party licenses.
- Upgrade and rollback procedures are documented.

## Proposed repository layout

```text
ProxyPilot/
├── src/                         # React UI
├── src-tauri/
│   ├── src/                     # Rust commands and services
│   └── capabilities/            # Minimal Tauri permissions
├── docs/
│   ├── PRODUCT-ARCHITECTURE.md
│   ├── ROADMAP-ACCEPTANCE.md
│   └── SECURITY-OPERATIONS.md
├── tests/
│   ├── fixtures/                # Sanitized, fake share links only
│   └── integration/
├── .github/
│   └── workflows/
└── README.md
```

## First implementation sequence

1. Scaffold the Tauri + React app and CI.
2. Implement the node import/parser with sanitized fixtures and unit tests.
3. Implement typed config generation and sing-box config-check integration.
4. Implement safe process lifecycle and port-conflict detection.
5. Implement endpoint table and explicit profile-to-node mapping.
6. Implement connectivity/egress tests and sanitized diagnostics.
7. Add DNS diagnostics and failure-isolation acceptance.
8. Package, review licenses, and publish a testable release candidate.

## Definition of done

A feature is not done merely because the UI renders. It needs tests, clear error states, security review for secrets/processes/filesystem access, documented acceptance steps, and verification on Windows. Never report a live proxy as healthy based only on mock UI data or a listening local port.
