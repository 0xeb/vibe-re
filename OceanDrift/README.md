# OceanDrift

Static reverse-engineering analysis of a 32-bit Windows implant that uses Microsoft Graph API (OneDrive) as its C2 transport.

## Sample

| Field | Value |
|-------|-------|
| SHA-256 | `f918849b5404c84103d9eff2f2b8e75e97724fc47f7f10078aed01d27ab8de54` |
| VirusTotal | [VT entry](https://www.virustotal.com/gui/file/f918849b5404c84103d9eff2f2b8e75e97724fc47f7f10078aed01d27ab8de54) |
| Family | Graphite (APT28 / Fancy Bear) |
| Architecture | 32-bit Windows PE |

## Analysis Tool

[idasql](https://github.com/0xeb/idasql) — SQL-driven analysis over the IDA database (`database.i64`) with Copilot CLI (Opus 4.6).

## Scope

- Config decryption (hex + 16-byte XOR)
- OAuth2 token refresh and Graph API session management
- OneDrive-based task polling and result delivery
- Command dispatch: `kill`, `shell`, `exec`, `upload`, `download`, `sleep`, `rest`
- Host fingerprinting (OS, MAC, WMI processor/disk IDs)
- Registry Run key persistence

## Repository Layout

| Path | Contents |
|------|----------|
| `docs/report.md` | Full technical analysis report with IOC catalog and MITRE mapping |
| `scripts/oceandrift.yar` | YARA rules (binary, config, memory scan) |
| `src/` | Compilable C++20 reconstruction of decompiled logic |
| `database.i64` | Annotated IDA database |

## Quick Start

**Read the report:**
- [docs/report.md](docs/report.md) — start at Section 4 (High-Level Workflow) for architecture, Section 7 for IOCs

**Build the reconstruction:**
```
cd src
cmake -B build -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

**Run YARA rules:**
```
yara scripts/oceandrift.yar <target>
```

## Disclaimer

This analysis is for **defensive security research and education only**.
See the repository [LICENSE](../LICENSE) and [Disclaimer](../README.md#disclaimer).
