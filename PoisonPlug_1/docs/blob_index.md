# ScatterBrain Plugin Blob Index

<a id="blob-index-overview"></a>
## Overview

The inner PE orchestrator registers 8 encrypted data blobs during `worker_thread_entry` initialization. Each blob is a ScatterBrain packed PE that, when decrypted (IMUL cipher) and decompressed (LZ77), reveals a **plugin DLL** following the same `DllMain_dispatcher` command protocol as the parent.

All plugins compiled 2017-02-22/23 (timestamps ~0x58AEBA). Each plugin:
- Uses fdwReason as command ID (0, 1, 100, 101, 102, 104)
- Exposes a small vtable via CMD 104
- Stores parent context via CMD 100
- Returns a version via CMD 101 and an ID string via CMD 102
- Uses the same polynomial XOR cipher for encrypted strings

For canonical protocol semantics and lifecycle details, see [how_plugins_work.md](how_plugins_work.md).
This index is based on query-driven `idasql` analysis; sensitive database and binary artifacts are kept in a private archive (see [ARTIFACT_ACCESS.md](../ARTIFACT_ACCESS.md)).

<a id="blob-index-plugin-registry"></a>
## Plugin Registry

| Blob | idasql Port | Role | Plugin ID | Version | Vtable Slots | Functions | Imports | Enc. Strings | Analysis |
|------|-------------|------|-----------|---------|-------------|-----------|---------|--------------|----------|
| blob_0 | 8200 | Process Launcher + Anti-Analysis | `Install` | 103 | 2 | 50 | 34 (5 DLLs) | 30 | [blob_0_install_analysis.md](blob_0_install_analysis.md) |
| blob_1 | 8201 | Registry Persistence | `Plugins` | 101 | 5 | 34 | 12 (3 DLLs) | 20 | [blob_1_plugins_analysis.md](blob_1_plugins_analysis.md) |
| blob_2 | 8202 | C2 Config / File Ops | 102 (int) | - | 3 | 27 | 0 (all dynamic) | 37 | [blob_2_config_analysis.md](blob_2_config_analysis.md) |
| blob_3 | 8203 | System Recon + C2 Router | `Online` | 104 | 14 | 55 | 31 (5 DLLs) | 56 | [blob_3_online_analysis.md](blob_3_online_analysis.md) |
| blob_4 | 8204 | Raw TCP + DNS Sockets | `TCP` | 200 | 6 | 23 | 21 (3 DLLs) | 13 | [blob_4_tcp_analysis.md](blob_4_tcp_analysis.md) |
| blob_5 | 8205 | HTTP POST Transport | `HTTP` | 201 | 6 | 42 | 38 (5 DLLs) | 17 | [blob_5_http_analysis.md](blob_5_http_analysis.md) |
| blob_6 | 8206 | Reliable UDP (RUDP) Transport | `UDP` | 202 | 6 | 55 | 21 (2 DLLs) | 7 | [blob_6_udp_analysis.md](blob_6_udp_analysis.md) |
| blob_7 | 8207 | DNS Tunnel Transport | `DNS` | 203 | 6 | 51 | 36 (2 DLLs) | 6 | [blob_7_dns_analysis.md](blob_7_dns_analysis.md) |

<a id="blob-index-import-breakdown"></a>
## Import Breakdown

### blob_0 — Process Launcher
5 DLLs: KERNEL32 (22), USER32 (4), ADVAPI32 (4), WS2_32 (2 ordinals), USERENV (2)
Key: CreateProcessW, OpenProcess, DuplicateTokenEx, OpenProcessToken, CreateToolhelp32Snapshot
Plaintext APIs: ImpersonateLoggedOnUser, RevertToSelf, CreateProcessAsUserW
Encrypted strings: SeTcbPrivilege, SeDebugPrivilege, winlogon.exe, Install, memset

### blob_1 — Registry Persistence
3 DLLs: KERNEL32 (6), USER32 (1), ADVAPI32 (5)
Key: RegOpenKeyExW, RegEnumValueW, RegDeleteValueW, RegCloseKey, RegQueryValueExW
Self-protection: SetUnhandledExceptionFilter, TerminateThread

### blob_2 — C2 Config / File Operations ("Config")
No static imports — resolves ALL APIs dynamically via parent context and encrypted strings.
37 encrypted strings reveal: protocol URLs (TCP/HTTP/HTTPS/UDP/DNS to 127.0.0.1:44444),
file I/O (CreateFileW, WriteFile, ReadFile, DeleteFileW), directory ops (CreateDirectoryW),
path expansion (%ALLUSERSPROFILE%\), system info (GetVolumeInformationW, GetSystemDirectoryW).
This is the **configuration and file management** module, NOT a simple shellcode stub.

### blob_3 — System Recon + C2 Router ("Online")
5 DLLs: KERNEL32 (13), USER32 (3), ole32 (2), WININET (11), VERSION (2)
Key: GetVersionExW, GetComputerNameW, GlobalMemoryStatusEx, GetNativeSystemInfo
HTTP: InternetOpenA, InternetConnectA, HttpOpenRequestA, HttpSendRequestExA, FtpOpenFileA
System: GetDiskFreeSpaceExA, EnumDisplaySettingsW, GetSystemMetrics

### blob_4 — Raw TCP + DNS Sockets ("TCP")
3 DLLs: KERNEL32 (5), USER32 (1), WS2_32 (15 ordinals + WSAIoctl)
Key: WSAIoctl, socket (ord#23), connect (ord#4), send (ord#19), recv (ord#16), select (ord#18)
Socket management: bind (ord#2), listen (ord#13), accept (ord#1), closesocket (ord#3)
Encrypted strings: HTTP/1.0 and HTTP/1.1 response parsing, **dnsapi.dll** (DnsQuery_A, DnsRecordListFree)

### blob_5 — HTTP POST Transport ("HTTP")
5 DLLs: KERNEL32 (20), USER32 (1), WS2_32 (4 ordinals), WININET (12), urlmon (1)
Key: HttpSendRequestExA, HttpEndRequestA, InternetReadFile, InternetSetOptionA/W
Unique: ObtainUserAgentString (urlmon) — spoofs legitimate browser user agent
Encrypted strings: "POST", "Content-Length: %d", SOCKS proxy support, "%s=%s:%d" format string

### blob_6 — UDP + DNS Transport ("UDP")
2 DLLs: KERNEL32 (21), WS2_32 (14 ordinals)
Key: socket, connect, send, recv, select, bind, listen, accept, closesocket
Encrypted strings: **dnsapi.dll** (DnsQuery_A, DnsRecordListFree), "UDP" protocol tag

### blob_7 — DNS Transport ("DNS")
2 DLLs: KERNEL32 (23), WS2_32 (13 ordinals)
Similar to blob_6 with additional: lstrcpyA, lstrlenA, LoadLibraryA, GetProcAddress
Encrypted strings: **iphlpapi.dll** (GetAdaptersAddresses), "DNS" protocol tag

<a id="blob-index-architecture"></a>
## Architecture

```
┌─────────────────────────────────────────────────┐
│              Inner PE (Orchestrator)              │
│                                                   │
│  worker_thread_entry                              │
│    └─ Register 8 encrypted blobs                  │
│    └─ For each blob:                              │
│         1. IMUL decrypt + LZ77 decompress         │
│         2. Validate magic 0x650001                │
│         3. Copy reflective loader to RWX          │
│         4. Load packed PE via loader              │
│         5. CMD 100 → store context                │
│         6. CMD 1   → populate vtable              │
│         7. CMD 104 → get vtable ptr               │
│         8. Register in plugin linked list         │
│                                                   │
│  Command routing:                                 │
│    └─ Incoming C2 command                         │
│    └─ Decrypt packet (IMUL cipher)                │
│    └─ Route to appropriate plugin                 │
│    └─ Plugin executes via vtable                  │
│    └─ Plugin can call back to parent              │
│         (context + 0x88 = injection)              │
│         (context + 0xD8 = state)                  │
└───────────────────┬───────────────────────────────┘
                    │
    ┌───────────────┼───────────────┐
    │               │               │
    ▼               ▼               ▼
  ┌─────────┐   ┌─────────┐   ┌──────────┐
  │ blob_0  │   │ blob_2  │   │ blob_3   │
  │"Install"│   │"Config" │   │ "Online" │
  │Process  │   │C2 Config│   │ Recon +  │
  │Launcher │   │+ File IO│   │ Router   │
  │+ Anti-  │   │         │   │          │
  │Analysis │   │TCP/HTTP/│   │CPU/Mem/  │
  └────┬────┘   │HTTPS/UDP│   │Disk/Net  │
       │        │DNS URLs │   │+ Proxy   │
       │        └─────────┘   └──────────┘
       │
       └──► Steals winlogon.exe token
            Creates process as SYSTEM
            Parent injects next plugin

  ┌──────────┐   ┌──────────────────────────────────┐
  │ blob_1   │   │         Transport Plugins          │
  │"Plugins" │   │                                    │
  │Registry  │   │  blob_4    blob_5   blob_6  blob_7│
  │Persist   │   │  "TCP"     "HTTP"   "UDP"   "DNS" │
  │SOFTWARE\ │   │  Raw TCP   HTTP     UDP+    DNS   │
  │Microsoft\│   │  + DNS     POST     DNS     +Adapter│
  └──────────┘   │  resolve   + SOCKS  resolve  enum │
                 └──────────────────────────────────┘
```

<a id="blob-index-files"></a>
## Files

### Reconstructed DLLs and IDA Databases

Artifacts in this table are listed for technical reference and are not distributed in this public repository.

| File | IDA Database | Plugin | Funcs |
|------|-------------|--------|-------|
| `blob_0_Install.dll.pe` | `blob_0_Install.dll.pe.i64` | Install (v103) | 50 |
| `blob_1_Plugins.dll.pe` | `blob_1_Plugins.dll.pe.i64` | Plugins (v101) | 34 |
| `blob_2_Config.dll.pe` | `blob_2_Config.dll.pe.i64` | Config (v102) | 27 |
| `blob_3_Online.dll.pe` | `blob_3_Online.dll.pe.i64` | Online (v104) | 55 |
| `blob_4_TCP.dll.pe` | `blob_4_TCP.dll.pe.i64` | TCP (v200) | 23 |
| `blob_5_HTTP.dll.pe` | `blob_5_HTTP.dll.pe.i64` | HTTP (v201) | 42 |
| `blob_6_UDP.dll.pe` | `blob_6_UDP.dll.pe.i64` | UDP (v202) | 55 |
| `blob_7_DNS.dll.pe` | `blob_7_DNS.dll.pe.i64` | DNS (v203) | 51 |

### Supporting Data

| File | Description |
|------|-------------|
| `blob_N_payload.bin` | Raw decompressed packed PE payloads (N=0..7) |
| `blob_pe_summary.json` | Complete metadata, imports, sections for all blobs |
| `blob_analysis.json` | Redacted public decryption/decompression summary |
| `blob_encrypted_strings.json` | Redacted public string inventory summary (counts only) |

<a id="blob-index-scripts"></a>
### Scripts

| File | Description |
|------|-------------|
| `scripts/sb_ciphers.py` | **Shared** cipher library (IMUL, polynomial XOR, rolling XOR) |
| `scripts/sb_packed_pe.py` | **Shared** packed PE parser (header, sections, imports) |
| `scripts/decrypt_blobs.py` | IMUL cipher + LZ77 decompressor |
| `scripts/decrypt_strings.py` | Encrypted string decryptor (supports any PE DLL, scan mode) |
| `scripts/reconstruct_blob_pes.py` | Packed PE → valid PE DLL reconstruction |
