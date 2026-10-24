# ProxyPilot 产品与技术架构

- 状态：Draft for implementation
- 产品：ProxyPilot Desktop
- 平台：Windows 10/11 x64（具体最低版本在构建验证后锁定）
- 核心：官方 sing-box 可执行文件，由桌面应用管理
- UI：Tauri + React + TypeScript
- 首版节点目标：10 个 HY2 节点；架构不硬编码为只能支持 10 个

## 1. 产品目标

为 Windows 用户提供一个可视化的本地代理管理器：导入 HY2 分享链接，管理节点，分配本地 SOCKS5 入口，将每个入口显式路由到一个指定出站，启动 sing-box，并逐个验证连通性和实际出口 IP。

产品重点是可验证的映射和运维体验，而不是实现新的代理协议。

## 2. 核心不变量

1. **一个 Profile → 一个本地入口 → 一个固定出站。** 映射必须可查看、可导出、可自动测试。
2. 默认只监听 `127.0.0.1`，不得默认监听局域网或公网地址。
3. 首版不配置负载均衡、随机选择或自动故障转移。
4. 节点故障时，对应入口应失败关闭；不得静默切换到另一个出口。
5. 节点分享链接、密码、混淆密码及生成配置中的秘密不写入日志、诊断报告或 Git 仓库。
6. 配置在启动前必须通过对应版本 sing-box 的配置校验。
7. “端口监听成功”“代理连通”“出口 IP 已验证”“DNS 路径已检查”是不同状态，不可合并成单一绿色状态。
8. 应用只能管理自己启动的 sing-box 进程；不得误杀其他 sing-box 或 v2rayN 进程。

## 3. 建议技术结构

```text
React UI (nodes / mappings / tests / logs)
          |
          | Tauri commands (typed request/response)
          v
Rust application services
  ├─ Node import & URI parsing
  ├─ Port allocation & conflict checks
  ├─ Config generation and validation
  ├─ sing-box process lifecycle
  ├─ Connectivity / egress test runner
  ├─ DNS diagnostics orchestration
  └─ Local persistence and redaction
          |
          ├─ App data: node metadata + protected secrets
          ├─ Generated runtime config (private ACL)
          └─ sing-box child process
                    |
                    ├─ 127.0.0.1:18001 -> HY2-01
                    ├─ 127.0.0.1:18002 -> HY2-02
                    └─ ... up to configured endpoint count
```

### UI

- React + TypeScript.
- Componentized pages: Overview, Nodes, Local Endpoints, Diagnostics, Logs, Settings.
- UI state is not the source of truth for process status; backend process state and test results are authoritative.
- Never expose secret query parameters in toasts, errors, tables, or copied diagnostics.

### Tauri / Rust backend

- Expose narrow, typed commands; do not provide a generic arbitrary shell command API.
- Launch sing-box using a fixed executable path and argument array, not shell-concatenated strings.
- Capture stdout/stderr and redact before display or persistence.
- Track the exact child process handle/PID created by the application.
- Validate all paths and port values; reject invalid or out-of-range values.
- Restrict filesystem access to the app data directory and explicitly selected import/export paths.

### sing-box integration

- Use a separately downloaded official sing-box binary; record version and checksum.
- Generate config from a typed internal model rather than string concatenation.
- Run `sing-box check -c <config>` before starting the core.
- Prefer one inbound tag per local endpoint, one outbound tag per node, and explicit route rules connecting each inbound to its assigned outbound.
- No catch-all fallback that could silently route an endpoint through a different node. Any final route behavior must be tested against the selected sing-box version.
- Bind SOCKS inbounds to loopback and optionally enable SOCKS authentication; credentials must be stored and displayed safely.
- Share-link options must be parsed and mapped according to the actual supported sing-box version. Do not assume all HY2 links have identical TLS, SNI, ALPN, or obfuscation parameters.

## 4. Data model (initial)

### Node

- `id`: stable UUID
- `name`: user-editable label
- `protocol`: initial value `hysteria2`
- `source_type`: pasted link / imported text file / manual entry
- `server_host`, `server_port`
- TLS metadata required by the link, including SNI where supplied
- Supported HY2 authentication and obfuscation parameters
- `enabled`, `created_at`, `updated_at`
- Secret fields stored separately from ordinary metadata where practical

### Endpoint / Profile mapping

- `id`: stable UUID
- `profile_name`
- `listen_host`: defaults to `127.0.0.1`
- `listen_port`: suggested 18001–18010, editable
- `node_id`: explicit target node
- Optional SOCKS authentication reference
- Last test result and timestamp (not treated as current truth without a new test)

### Test result

- endpoint and node IDs
- test kind: local listener / proxy connectivity / egress IP / DNS diagnostic / isolation
- started/finished timestamps
- success/failure/unknown
- observed IP and test service, if any
- sanitized error category and short diagnostic
- no passwords, raw share links, or full generated config

## 5. Main screens

### Overview

- Core state: stopped / starting / running / stopping / error
- Counts for configured nodes, listener status, last successful tests, and failed tests
- Start, stop, restart, validate-config actions
- Clear separation between runtime health and last test status

### Nodes

- Paste one or multiple `hy2://` links or import a text file (one link per line)
- Parse and preview node label, host, port, SNI, and whether obfuscation parameters are present
- Mask secrets by default
- Validate malformed links and duplicate entries
- Allow rename, enable/disable, edit supported fields, delete
- Show import errors per line without echoing the full secret URL

### Local endpoints

- Table mapping Profile → 127.0.0.1 port → outbound node
- Automatic port suggestion plus collision check
- Explicit rebind action with confirmation
- Never infer a profile mapping solely from row order after the user has edited mappings

### Diagnostics

- Per-node test and batch test
- Local listener availability
- Proxy request through each SOCKS endpoint
- Egress IP observation
- DNS test guidance and results with limitations stated
- Controlled failure-isolation test with explicit user confirmation
- Export sanitized report

### Logs

- Application events and sing-box output with secret redaction
- Filter by time, endpoint, node, severity
- No raw credential-bearing URI or full config dumps

## 6. Configuration generation

1. Parse share links into a typed model and preserve only supported, understood parameters.
2. Validate required fields and warn on unknown or unsupported query parameters; never silently drop security-relevant settings.
3. Create unique inbound and outbound tags.
4. Generate explicit inbound-to-outbound routing rules.
5. Validate port uniqueness and listener host.
6. Write config atomically with restrictive Windows ACLs.
7. Run the selected binary's config checker.
8. Start only after validation succeeds.
9. On config replacement, keep the last known-good config for rollback.
10. Redact secrets from any displayed validation errors before rendering.

## 7. DNS and browser behavior

A successful `curl --proxy socks5h://...` request confirms a proxied request using SOCKS remote name resolution for that test; it does **not** prove that all browser DNS traffic follows the same path.

DNS diagnostics must distinguish:
- DNS used by the application for the proxy server hostname
- name resolution requested through SOCKS
- browser Secure DNS / DoH behavior
- system-level DNS and other applications
- observed public DNS resolvers from an external test

The first release should report what it actually tested and provide manual browser verification steps. Do not label an endpoint “DNS leak-free” based on one test.

## 8. Process lifecycle and coexistence

- v2rayN remains installed and untouched.
- ProxyPilot must not change system proxy settings or install a TUN adapter in v1.
- Check configured local ports before launch; report conflicts with PID/process name where available.
- Never terminate an unrelated process to free a port.
- Stop only the child process launched by ProxyPilot; handle graceful shutdown and timeout.
- After unexpected exit, mark state as failed and require an explicit retry or a clearly disclosed recovery policy.

## 9. Licensing and distribution gate

Before distributing a packaged application, review the licenses and notices for Tauri dependencies and the exact sing-box version/binary being bundled or downloaded. Keep third-party notices and source-offer/compliance obligations where applicable. Do not assume that an open-source dependency can be redistributed without satisfying its license terms.

## 10. Out of scope for v1

- System-wide transparent proxy / TUN
- Remote management or cloud sync
- Subscription provider integrations beyond plain-text share-link import
- Automatic IP rotation, random routing, load balancing, or failover
- Browser fingerprint modification
- A replacement for v2rayN
