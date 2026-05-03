# Technical Malware Analysis Report (Static)

## 1. Executive Summary
This report documents a static reverse-engineering assessment of a 32-bit Windows sample analyzed in IDA via SQL-only extraction (IDASQL tables/functions, no IDAPython).

The sample implements a Graph/OneDrive-backed tasking model with OAuth refresh-token authentication, command execution, file transfer, host profiling, and optional persistence via Windows Run key.

At a high level, the binary:
- Loads configuration from `config.dat`/`config.json`.
- Supports encrypted config blobs prefixed with `ENCR:` and decoded with a custom hex+XOR routine.
- Establishes Microsoft Graph API session state, refreshes access tokens, and builds per-agent cloud paths.
- Polls remote task endpoints, executes commands (`kill`, `shell`, `exec`, `upload`, `download`, `sleep`, `rest`), and posts results.
- Creates host metadata artifacts and heartbeat signals (`info.txt`, `alive.txt`).

Static confidence for core capability claims is high. Final operational confidence still requires dynamic validation.

---

## 2. Scope, Method, and Constraints
### Scope
- Static-only assessment from IDA database via SQL queries.
- Decompilation, function mapping, IOC extraction, and capability inference.

### Method
- SQL table introspection (`funcs`, `pseudocode`, `imports`, `disasm_calls`, `segments`, `db_info`, `ida_info`, `welcome`).
- Cross-referenced function and pseudocode evidence by address and line number.
- Targeted renaming of key Graph/Beacon routines through SQL updates.

### Constraints
- **No IDAPython used in this final report workflow** (user requirement).
- Fields that typically require direct file access (full sample hash/timestamp provenance from file bytes/path) are marked as unavailable under SQL-only constraints.

---

## 3. Sample and Environment Metadata

### Sample Identification
- **SHA-256:** `f918849b5404c84103d9eff2f2b8e75e97724fc47f7f10078aed01d27ab8de54`
- **VirusTotal:** [VT entry](https://www.virustotal.com/gui/file/f918849b5404c84103d9eff2f2b8e75e97724fc47f7f10078aed01d27ab8de54)
- **Family:** Graphite (APT28 / Fancy Bear)

### IDA Database Metadata (SQL-observed)
From `welcome`, `db_info`, and `segments`:

- Processor: `metapc`
- Bitness: `32-bit`
- Address range: `0x400000` - `0x4ED000`
- Start EA: `0x48EAD8`
- Main EA: `0x426350`
- Function count: `3760`
- Segment layout:
  - `HEADER`
  - `.text`
  - `.idata`
  - `.rdata`
  - `.data`
  - `.rsrc`
  - `.reloc`

Interpretation:
- Standard PE section layout with no obvious packed section naming.
- Presence of encrypted config decode logic indicates selective obfuscation of configuration rather than whole-binary packing.

---

## 4. High-Level Workflow
1. Parse arguments and optional `--autostart` handling.
2. Attempt configuration load from `config.dat` then `config.json`.
3. If payload starts with `ENCR:`, decode via hex parse + XOR key stream.
4. Parse `GraphAPI` config object and refresh token fields.
5. Initialize Graph API session and refresh access token.
6. Build machine GUID and cloud endpoint paths.
7. Initialize remote task paths (`/job`, `/result`, `/upload`, `/download`).
8. Enter worker loop:
   - enumerate task files (`task.lock`, `task_*`),
   - download task payload,
   - parse command/params,
   - execute command,
   - publish results with status.
9. Maintain heartbeat/host info files (`alive.txt`, `info.txt`).

### Operator Workflow Diagram
```text
[Startup]
   |
   v
Read config.dat/config.json --> If ENCR: decode_hex_xor_payload()
   |
   v
GraphAPI init + refresh token
   |
   v
Build agent path + /job /result /upload /download
   |
   v
Poll task files (task.lock, task_*)
   |
   +--> shell/exec --> local process execution --> capture output
   |
   +--> upload/download --> Graph Drive content ops
   |
   +--> sleep/rest/kill --> control flow / termination
   |
   v
Publish result status (inprogress/completed/failed)
   |
   v
Heartbeat artifacts (alive.txt, info.txt) + repeat loop
```

---

## 5. Core Capability Analysis
## 5.1 Persistence
### Registry Run Key persistence
- Function: `handle_autostart_flag` (`0x401220`)
- Evidence:
  - `RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", ...)` (line 52)
  - `RegSetValueExA(...)` (line 60)

Assessment:
- Implements user-level autorun persistence (`HKCU\...\Run`).

## 5.2 Configuration and Crypto/Obfuscation
### Config sources
- `_main` (`0x426350`):
  - attempts `config.dat` (lines 736, 753, 806)
  - attempts `config.json` (lines 883, 900, 949)

### Encrypted config handling
- `load_config_from_file` (`0x423EC0`):
  - checks marker `"ENCR:"` (line 172)
  - calls `decode_hex_xor_payload` (line 212)
  - requires `"GraphAPI"` member (line 296)

### Decode routine
- `decode_hex_xor_payload` (`0x424810`):
  - hex decode via `strtol(..., 16)` (line 222)
  - XOR against `byte_4D6C44[...]` (line 118)
  - 16-byte cyclic key (index `& 0xF`):
    ```
    8A 4B 2C D3 F1 E5 7A 9B 3D 6F 1C 8E 5B 2A D7 C9
    ```

Assessment:
- Config can be stored plaintext JSON or encoded payload with weak reversible XOR scheme.

## 5.3 Graph/OAuth Control Plane
### OAuth token refresh
- `graph_api_refresh_access_token` (`0x428A00`):
  - `https://login.microsoftonline.com/` (line 117)
  - `/oauth2/v2.0/token` (line 119)
  - body components:
    - `client_id=` (line 152)
    - `&client_secret=` (line 154)
    - `&refresh_token=` (line 162)
    - `&grant_type=refresh_token` (line 170)
  - response fields parsed:
    - `access_token` (line 505 / 510)
    - `refresh_token` (line 520 / 525)
    - `expires_in` (line 537 / 542)

### Graph base
- `graph_api_session_create` (`0x4195B0`):
  - `https://graph.microsoft.com/v1.0` (line 37)

### Auth headers
- `graph_api_request_json` (`0x429630`), `graph_api_download_item_content` (`0x42BE40`), `graph_api_upload_item_content_from_file` (`0x42C400`):
  - construct `Authorization: Bearer ...`

Assessment:
- Clear dependency on valid Microsoft identity token chain and Graph REST operations.

## 5.4 Drive-based Tasking and Data Movement
### Session path initialization
- `beacon_initialize` (`0x40F4A0`):
  - scope: `offline_access Files.Read Files.ReadWrite` (lines 68, 98)
  - endpoints:
    - `/job` (line 172)
    - `/result` (line 191)
    - `/upload` (line 210)
    - `/download` (line 230)

### OneDrive API wrappers (renamed)
- `graph_api_list_root_children` (`0x42AF70`)
- `graph_api_list_children_by_item_id` (`0x42B340`)
- `graph_api_get_item_by_id` (`0x42B7D0`)
- `graph_api_get_item_by_path` (`0x42BAB0`)
- `graph_api_download_item_content` (`0x42BE40`)
- `graph_api_upload_item_content_from_file` (`0x42C400`)
- `graph_api_delete_item_by_id` (`0x42CAB0`)
- `graph_api_delete_item_by_path` (`0x42CD60`)
- `graph_api_upload_content_by_path` (`0x42CE10`)
- `graph_api_create_upload_session_by_path` (`0x42D240`)
- `graph_api_create_folder_under_item` (`0x42ECD0`)
- `graph_api_rename_item_by_path` (`0x42F2B0`)

Notable REST fragments:
- `/me/drive/root/children`
- `/me/drive/items/<id>`
- `/me/drive/root:/<path>`
- `:/content`
- `:/createUploadSession`

### Upload session semantics
- `graph_api_create_upload_session_by_path` (`0x42D240`):
  - JSON includes `item`, `@microsoft.graph.conflictBehavior`, value `rename`
  - parses `uploadUrl` and `expirationDateTime`

Assessment:
- The implant uses Graph Drive semantics as C2/task transport and file staging layer.

## 5.5 Command Execution Engine
### Dispatcher
- `execute_beacon_command` (`0x411220`) matches:
  - `kill` (line 161)
  - `shell` (line 169)
  - `exec` (line 292)
  - `upload` (line 394)
  - `download` (line 498)
  - `sleep` (line 674)
  - `rest` (line 742)

### Action routines
- `run_shell_and_capture_output` (`0x412560`)
  - Builds command: `<cmd> > "%TEMP%\beacon_shell_output.txt" 2>&1`
  - Reads temp file back into beacon context output buffer (+476), then deletes it
- `spawn_process_detached` (`0x412DF0`)
  - `MultiByteToWideChar` with code page `0xFDE9` (non-standard value), then `CreateProcessW` fire-and-forget
- `upload_local_file_to_agent_path` (`0x4134B0`)
- `beacon_kill_now` (`0x412550`)

### Input validation/errors
- Missing upload params error:
  - `"Missing required parameters: onedrive_path and/or agent_path"` (line 470)
- Download param type error:
  - `"Download parameter must be a string file path"` (line 505)
- Unknown command:
  - `"Unknown command: "` (line 802)
- Generic failed execution:
  - `"Command execution failed"` (line 883)

Assessment:
- Full remote command-and-file-control implant behavior.

## 5.6 Host Discovery/Fingerprinting
### Profile construction
- `build_host_profile_json` (`0x4039E0`) emits:
  - `IP Address`
  - `Operating System`
  - `Host Name`
  - `User Name`
  - `Workgroup`
  - `MAC Address`
  - `Privilege`
  - `Time Zone`

### OS version detection
- `get_os_version` (`0x404410`):
  - Dynamically loads `RtlGetVersion` from `ntdll.dll` via `GetModuleHandleA` + `GetProcAddress` (bypasses deprecated `GetVersionEx`)
  - Calls `GetProductInfo` for workstation vs. server SKU distinction
  - Maps `major.minor.build` to display names (Windows 7 through Windows 11, Server 2016/2019/2022)

### Hardware identifiers
- `get_primary_mac_address` (`0x4049C0`) via `GetAdaptersInfo`
- `wmi_get_processor_id` (`0x405110`) query:
  - `SELECT ProcessorId FROM Win32_Processor`
- `wmi_get_physical_media_serial` (`0x405610`) query:
  - `SELECT SerialNumber FROM Win32_PhysicalMedia`
- `build_host_machine_guid` (`0x405B10`) builds GUID-like string from processor ID + disk serial + MAC

Assessment:
- Host fingerprinting is used to identify/partition agent instances.
- Dynamic ntdll resolution avoids static import of `RtlGetVersion`.

---

## 6. Hardcoded and Semi-Hardcoded Data
From `_main` (`0x426350`):
- Redirect URI: `http://localhost/` (line 681)
- Client ID: `675b5280-b233-4368-ba9e-b4c55cbeebe9` (line 686)
- Tenant ID: `e2aa8d24-85a2-41e6-b993-572b35980557` (line 691)
- Client Secret: `gVd8Q~r5QwHkIb3NsNraqGLUPwlhnngrpYcSKbjl` (line 696)

Config override getters exist (`get_graphapi_client_id`, `_tenant_id`, `_client_secret`, `_redirect_uri`) and pull from `GraphAPI` JSON object.

---

## 7. IOC Catalog
## 7.1 Network/Protocol IOCs
- `https://graph.microsoft.com/v1.0`
- `https://login.microsoftonline.com/`
- `/oauth2/v2.0/token`
- `Authorization: Bearer`
- `client_id=`, `client_secret=`, `refresh_token=`, `grant_type=refresh_token`
- `offline_access Files.Read Files.ReadWrite`

## 7.2 C2/Task Path IOCs
- `/job`
- `/result`
- `/upload`
- `/download`
- `/me/drive/root/children`
- `/me/drive/items/`
- `/me/drive/root:/`
- `:/content`
- `:/createUploadSession`

## 7.3 Host/Filesystem/Registry IOCs
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `config.dat`
- `config.json`
- `ENCR:`
- `alive.txt`
- `info.txt`
- `task.lock`
- `task_` prefix
- `beacon_shell_output.txt`

## 7.4 Command Vocabulary IOCs
- `kill`
- `shell`
- `exec`
- `upload`
- `download`
- `sleep`
- `rest`
- `Unknown command:`

## 7.5 Config Schema IOCs
- `GraphAPI`
- `refreshToken`
- `access_token`
- `refresh_token`
- `expires_in`
- `agent_path`
- `onedrive_path`

## 7.6 Crypto/Obfuscation IOCs
- XOR key (16 bytes at `0x4D6C44`): `8A 4B 2C D3 F1 E5 7A 9B 3D 6F 1C 8E 5B 2A D7 C9`
- Config marker prefix: `ENCR:` (5 bytes)
- Code page `0xFDE9` passed to `MultiByteToWideChar` in process spawn path

---

## 8. MITRE ATT&CK Mapping (Preliminary)
- `T1547.001` Registry Run Keys / Startup Folder (autostart flag path)
- `T1071.001` Application Layer Protocol: Web Protocols (Graph HTTP API)
- `T1105` Ingress Tool Transfer (upload/download handlers)
- `T1059.003` Command and Scripting Interpreter: Windows Command Shell (`shell` command)
- `T1027` Obfuscated/Compressed Files and Information (ENCR + XOR config)
- `T1082` System Information Discovery (host profile, WMI identifiers)
- `T1106` Native API (dynamic `RtlGetVersion` resolution from `ntdll.dll` via `GetProcAddress`)
- `T1567.002` Exfiltration Over Web Service: Exfiltration to Cloud Storage (file upload to OneDrive)
- `T1074.001` Data Staged: Local Data Staging (`%TEMP%\beacon_shell_output.txt` for shell output capture)
- `T1497` Virtualization/Sandbox Evasion (low confidence; sleep/rest may be operational delay but no dedicated anti-VM proof yet)

---

## 9. Detection and Hunting Recommendations
## 9.1 Host telemetry
- Alert on suspicious writes to:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Alert on unusual process behavior around:
  - detached process creation after cloud-file task polling
  - recurring short-lived command execution with staged result uploads

## 9.2 Network telemetry
- Detect OAuth token refresh and Graph Drive API patterns from non-standard enterprise apps:
  - `login.microsoftonline.com/*/oauth2/v2.0/token`
  - Graph endpoints with high-frequency tasking cadence and small artifact files
- Correlate client app identifiers/secrets observed in process memory/command artifacts.

## 9.3 File/content analytics
- Hunt for local artifacts:
  - `config.dat`, `config.json`, `alive.txt`, `info.txt`, `task.lock`
- Detect JSON objects containing command schema keys (`command`, `params`, `agent_path`, `onedrive_path`) in cloud/file logs.

## 9.4 Behavioral correlation
- Sequence to detect:
  1. Config read/decode (`ENCR:` path)
  2. OAuth refresh to Microsoft login endpoint
  3. Graph Drive task/file operations
  4. Local execution + status/result update (`inprogress/completed/failed`)

---

## 10. Confidence, Gaps, and Next Validation Steps
## Confidence
- High confidence in static capability claims:
  - persistence, tasking model, command dispatch, Graph API usage, config decode.
- Medium confidence in operational deployment profile:
  - requires dynamic validation in controlled sandbox.

## Gaps (under SQL-only constraint)
- No runtime packet captures or process-tree confirmation yet.
- No confirmed dedicated anti-analysis branch in core beacon path.

## Dynamic validation plan (recommended)
1. Controlled execution with full process/network tracing.
2. Confirm token refresh + Drive endpoint sequence and periodicity.
3. Execute representative command set (`shell`, `exec`, `upload`, `download`, `sleep/rest`) and capture exact artifact lifecycle.
4. Validate persistence branch behavior (`--autostart`) and cleanup semantics.

---

## 11. Appendix: Key Function Map
- `0x401220` `handle_autostart_flag`
- `0x4039E0` `build_host_profile_json`
- `0x4049C0` `get_primary_mac_address`
- `0x405110` `wmi_get_processor_id`
- `0x405610` `wmi_get_physical_media_serial`
- `0x405B10` `build_host_machine_guid`
- `0x40F4A0` `beacon_initialize`
- `0x410320` `beacon_worker_loop`
- `0x411220` `execute_beacon_command`
- `0x412560` `run_shell_and_capture_output`
- `0x412DF0` `spawn_process_detached`
- `0x4134B0` `upload_local_file_to_agent_path`
- `0x414D50` `download_remote_task_file_by_agent_path`
- `0x4150D0` `publish_task_result`
- `0x423EC0` `load_config_from_file`
- `0x424810` `decode_hex_xor_payload`
- `0x428A00` `graph_api_refresh_access_token`
- `0x429630` `graph_api_request_json`
- `0x42AF70` `graph_api_list_root_children`
- `0x42BE40` `graph_api_download_item_content`
- `0x42C400` `graph_api_upload_item_content_from_file`
- `0x42D240` `graph_api_create_upload_session_by_path`
- `0x42ECD0` `graph_api_create_folder_under_item`
- `0x42F2B0` `graph_api_rename_item_by_path`
- `0x404410` `get_os_version`

---

## 12. Appendix: C++ Source Reconstruction

A compilable C++20 reconstruction of the decompiled logic is maintained in `src/`. It preserves original IDA addresses in comments and struct field offsets matching binary layout. Key files:

| File | Reconstructs |
|------|-------------|
| `main.cpp` | Entry point and 9-phase startup orchestration |
| `config.cpp` | Config loading and XOR decode routine |
| `graph_api.cpp` | OAuth token refresh and Graph API HTTP requests |
| `beacon.cpp` | Beacon context, worker threads, command dispatch |
| `host_profile.cpp` | OS/hardware fingerprinting and WMI queries |
| `persistence.cpp` | Registry Run key and Startup folder persistence |
| `runtime.cpp` | Utility wrappers (paths, JSON, proxy, curl) |
| `catalog.cpp` | Evidence aggregation |

Known gaps in the reconstruction are documented in `src/missing.md` (signature mismatches, undefined symbols, commented-out placeholder blocks).
