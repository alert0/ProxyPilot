# ProxyPilot 安全与运维规范

## 1. Secrets handling

HY2 share links may contain server names, authentication passwords, SNI, and obfuscation secrets. Treat the complete link as a credential.

- Never commit real links, passwords, generated production configs, logs, crash dumps, or screenshots containing secrets.
- Mask credentials by default in the UI.
- Redact URI userinfo, password fields, obfuscation passwords, and sensitive query parameters from errors and logs.
- Do not include secrets in telemetry; the first release should have no telemetry by default.
- Store node passwords and obfuscation secrets through Windows Credential Manager via the `keyring` crate; metadata JSON contains no credentials.
- The runtime config must temporarily contain plaintext credentials for sing-box. The app now attempts to restrict its dedicated config directory ACL with `icacls.exe` to the current user, SYSTEM, and local Administrators; if ACL restriction fails, config writing is blocked.
- Runtime config is written atomically and removed on normal stop/app exit. A forced termination or OS crash can leave the file behind; recovery/cleanup UX and a Windows ACL acceptance test remain required.
- Document Windows account/profile binding and backup implications before release.
- Exports must exclude secrets by default; require a clear confirmation before any full-fidelity export.

## 2. Local listener security

- Bind SOCKS listeners to `127.0.0.1` by default.
- Do not expose listeners on `0.0.0.0`, LAN, or public interfaces unless a future feature adds explicit warning and authentication requirements.
- Validate ports and reject duplicates.
- Optional SOCKS credentials should be supported where appropriate; do not confuse SOCKS authentication with encryption on the local loopback.
- Do not automatically change Windows Firewall rules.

## 3. Process execution

- Start the core with a fixed executable path and argument list.
- Do not interpolate user-provided node values into shell commands.
- Restrict the Tauri command surface; no generic shell execution command.
- Track the process handle/PID started by the app and stop only that process.
- Do not kill processes merely because they occupy a configured port.
- Validate the core binary path and record the version/checksum for diagnostics.
- Do not auto-update or replace the core without user-visible version information and a recovery path.

## 4. Configuration lifecycle

- Generate config from typed structures, not string concatenation.
- Validate the generated config with the selected sing-box binary before launch.
- Keep a last-known-good config for rollback, with restrictive permissions.
- Avoid showing full config in the UI. If advanced config inspection is later added, redact secrets by default.
- Never silently remove an unknown security-relevant share-link parameter. Warn or block launch until supported or explicitly resolved.
- No automatic failover in v1. A failed node must not silently use a different outbound.

## 5. Diagnostics and logs

- Logs should contain timestamps, component, severity, node/endpoint IDs, and sanitized error categories.
- Avoid logging full share links, raw config, authentication headers, or command arguments that include secrets.
- Diagnostic bundles must be reviewed/redacted before export.
- Keep logs local and define a retention/rotation policy before release.
- Distinguish process state, listener state, remote connectivity, egress observation, and DNS diagnostics.

## 6. DNS and browser test limitations

- A SOCKS5 remote-resolution test is not proof that browser DNS, DoH, WebRTC, or other applications cannot bypass the proxy.
- State exactly which test was run and when.
- Browser-level tests should be performed in each intended browser profile.
- Do not claim “DNS leak-free” without a defined threat model and repeatable evidence.
- Egress IP services are external dependencies; handle their failures separately from proxy failures.

## 7. v2rayN coexistence

- Do not modify v2rayN config, shortcuts, system proxy, startup behavior, or running processes.
- Use a separate default port range (18001–18010) and check for conflicts.
- If v2rayN already occupies a selected port, offer a safe port change instead of terminating the process.
- Do not assume v2rayN and ProxyPilot can share a single inbound port.

## 8. Release checklist

- [ ] No secrets in repository history, test fixtures, CI logs, or release assets.
- [ ] Tauri capabilities are minimal and reviewed.
- [ ] Generated runtime config ACLs verified on Windows. (ACL restriction code is present; manual verification is pending.)
- [ ] Core launch/stop tested without affecting unrelated processes.
- [ ] Port-conflict behavior tested.
- [ ] Config-check failure blocks startup.
- [ ] Single-node failure does not silently change another endpoint's route.
- [ ] DNS claims accurately describe test coverage.
- [ ] Third-party licenses/notices reviewed for exact shipped versions.
- [ ] Upgrade, rollback, uninstall, and data-removal behavior documented.
