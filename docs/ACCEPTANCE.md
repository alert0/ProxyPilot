# Acceptance evidence

The v0.2.0 implementation completes the local first-release application workflows. Product acceptance still requires distinguishing source checks, Windows process integration, live-node networking, browser checks, and clean-machine distribution checks.

## Automated

- Unit tests cover link/Base64 import, metadata/vault separation, custom port uniqueness, save rollback, restore validation, credential repair, route isolation, IP responses, bounded history, tool timeout, URL validation and SHA-256 corruption.
- `examples/core_acceptance.rs` checks the selected official core on 1/2/10 synthetic nodes: config check, occupied-port rejection, loopback listener readiness, stop and runtime credential-file removal. It never reads the user's node store and never claims remote connectivity.
- Release packaging includes source, a dependency inventory and available third-party notices. Core downloads are independently verified and retained with provenance.

## User/environment acceptance

- Real HY2 requests through each configured profile and configurable HTTPS services.
- Confirmed failure injection and recovery on multiple healthy real nodes.
- Browser DoH/system DNS/WebRTC observations per intended browser profile.
- Clean supported Windows machine launch/import/check/stop/uninstall and coexistence with the user's v2rayN.
- Public release licensing selection/review and exact release environment/version evidence.

These checks are not marked passed merely because builds or synthetic tests pass. Local results from this implementation session are recorded below after execution.

## 2026-10-25 local evidence

- Rust 1.99.1 / Windows x64: compile and format checks passed.
- 38 unit tests passed; release Clippy with all targets/features and warnings denied passed.
- Official sing-box 1.14.4: 1/2/10-node configuration checks, occupied-port rejection, listener startup, stop and runtime-file cleanup passed.
- Native Windows Credential Manager: unique synthetic credential set/get/delete passed.
- Real loopback HY2 fixture: two independent SOCKS-to-HY2 routes completed remote-name HTTPS requests. Baseline, selected-outbound failure, unaffected-route success and recovery passed using `https://icanhazip.com/` for IP queries. This exercises real HY2 transport locally, not a user's remote server.
- `https://api.ipify.org` produced curl TLS handshake errors on this direct test path while other HTTPS targets succeeded. The workflow correctly refused failure injection without successful baselines; no failed query was reported as healthy. Targets are configurable.
- Desktop smoke check: overview, settings, diagnostics navigation, scrolling and availability of backup/restore controls verified. No production node was modified or tested during the smoke check.
- A clean Windows machine, production remote HY2 nodes, browser DNS/WebRTC and public distribution licensing have not been certified by these local tests.
