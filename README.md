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
- Tauri + React UI; Rust/Tauri backend for process and filesystem operations.
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
- [Implementation plan](docs/IMPLEMENTATION-PLAN.md)
- [Development roadmap and acceptance](docs/ROADMAP-ACCEPTANCE.md)
- [Security and operations](docs/SECURITY-OPERATIONS.md)

## Safety and privacy

HY2 share links can contain credentials and server metadata. Keep them local, redact secrets from logs, and never commit real links or generated production configuration to the repository. Bind local SOCKS listeners to `127.0.0.1` by default.

## Development status

Current status: design and implementation plan committed. Runtime application code has not yet been committed; follow `docs/IMPLEMENTATION-PLAN.md` from M0.
