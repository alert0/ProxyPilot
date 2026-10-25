# Changelog

## 0.2.1

- Official core downloads retry transient failures and use explicit connection/transfer timeouts.
- Download errors identify curl exit codes and HTTP status without exposing proxy credentials or raw tool output.

## 0.2.0

- Working overview, node, mapping, diagnostics, log and settings pages with scrolling.
- Native Windows Credential Manager backend enabled; no plaintext secret export.
- Editable Profile/port mappings with duplicate checks and transactional metadata updates.
- Background operations, busy protection, instance lock, automatic runtime state refresh.
- Persisted core selection, settings and checksum; official Windows x64 core downloader verifies GitHub asset SHA-256.
- Bounded external tool execution, listener readiness, restart rollback and temporary config cleanup.
- Configurable HTTPS diagnostic targets, bounded batch concurrency, timestamped history and export.
- Confirmed app-local failure isolation with baseline, selected-node failure, unaffected-node checks and recovery.
- Metadata backup/restore, credential re-import repair, local lifecycle logs.
- Windows portable package script, dependency license inventory and local core acceptance example.

Live HY2/DNS/WebRTC and clean-machine acceptance are distinct from automated checks. See docs/ACCEPTANCE.md.
