# Blob 5 — HTTP POST Transport Plugin ("HTTP")

## Summary

| Property | Value |
|----------|-------|
| File | Private archive artifact (available on vetted request) |
| Image Size | 0x8000 (32768 bytes) |
| Entry Point RVA | 0x157C |
| Functions | 42 (all renamed) |
| Sections | .text, .rdata, .data2, .data3, .idata |
| Timestamp | 0x58AEBA (2017-02-22/23) |
| idasql Port | 8205 |
| Version (CMD 102) | 201 |
| Plugin Name (CMD 103) | `"HTTP"` (encrypted at `0x180004158`) |
| Protocol Variants | 201 (HTTP), 204 (HTTPS) |

## Role

**WinInet-based HTTP/HTTPS C2 transport.** Implements reliable, ordered, bidirectional data channel over HTTP POST requests. All traffic encrypted with rolling XOR cipher. User agent spoofed via `urlmon!ObtainUserAgentString`. Supports SOCKS and HTTP proxy with authentication. Custom sequence numbering for reliable delivery over stateless HTTP.

## Imports (38 functions, 5 DLLs)

### KERNEL32.dll (20)
InitializeCriticalSection, DeleteCriticalSection, EnterCriticalSection, LeaveCriticalSection, QueryPerformanceCounter, CreateThread, GetLastError, WaitForSingleObject, CloseHandle, Sleep, CreateEventW, GetSystemTime, GetTickCount, GetCurrentThreadId, GetCurrentProcessId, ResetEvent, SetEvent, lstrcpyA, lstrlenA, +more

### USER32.dll (1)
wsprintfA

### WS2_32.dll (4 ordinals)
ntohs, htons, WSAStartup, WSACleanup

### WININET.dll (12)
InternetSetOptionA/W, InternetCloseHandle, InternetReadFile, HttpQueryInfoA, HttpEndRequestA, InternetOpenA, InternetConnectA, HttpOpenRequestA, InternetQueryOptionW, HttpSendRequestExA, HttpAddRequestHeadersA

### urlmon.dll (1)
**ObtainUserAgentString** — spoofs legitimate browser user agent

## Entry Point: DllEntryPoint (0x18000157C)

| fdwReason | Command | Action |
|-----------|---------|--------|
| 0 | DETACH | No-op |
| 1 | ATTACH | Populates 6-slot vtable at `0x180005000` |
| 100 | START | WSAStartup + CreateThread(transport_manager_poll_thread) |
| 101 | STOP | Wait for poll thread, cleanup, WSACleanup |
| 102 | VERSION | Returns 201 |
| 103 | NAME | Decrypts "HTTP" |
| 104 | VTABLE | Returns vtable pointer |

## Vtable (6 slots at `0x180005000`)

| Slot | Address | Name | Purpose |
|------|---------|------|---------|
| 0 | 0x180001074 | `vtbl_create_connection` | Allocate 4448-byte connection, init buffers |
| 1 | 0x18000114C | `vtbl_connect` | Validate protocol, copy config, spawn worker |
| 2 | 0x180001208 | `vtbl_send` | Queue send data, signal event, wait completion |
| 3 | 0x180001320 | `vtbl_recv` | Queue recv buffer, signal event, wait completion |
| 4 | 0x180001438 | `vtbl_shutdown` | Signal WSAECONNABORTED (10053) |
| 5 | 0x180001474 | `vtbl_close` | Wait 60s for drain, stop worker, cleanup |

## HTTP Protocol Details

### Request Format
- **Method**: `POST`
- **Path**: `/` (root)
- **Accept**: `*/*`
- **Content-Length**: Added via HttpAddRequestHeadersA

### Connection Flags
- HTTP (201): `0x8440F100` — RELOAD, NO_CACHE_WRITE, KEEP_CONNECTION, ignore redirects/cert errors
- HTTPS (204): Adds `INTERNET_FLAG_SECURE` (0x00800000)

### HTTPS Certificate Bypass
After HttpOpenRequestA, queries `INTERNET_OPTION_SECURITY_FLAGS` (31), ORs in `0xF380` (all certificate ignore flags), sets back. Bypasses: revocation, unknown CA, wrong usage, CN invalid, date invalid, redirect.

### Timeouts
| Option | Value |
|--------|-------|
| Connect timeout | 30,000ms |
| Send timeout | 90,000ms |
| Receive timeout | 90,000ms |
| Max conns/server | 100 |

### User Agent Spoofing
`ObtainUserAgentString(0, buf, &size)` from `urlmon.dll` retrieves the system's default browser UA string (typically IE from registry). Makes C2 traffic appear as legitimate browsing.

## Data Encoding: Rolling XOR Cipher

**Key derivation**: Seed = low 16 bits of `QueryPerformanceCounter()`.

**LCG formula**: `key = 0x77920000 * key - 0x4EDC886E * (key >> 16) - 0x7916409E`

Each byte XORed with `key & 0xFF`. Seed transmitted in cleartext as first 2 bytes (htons).

### Packet Structure

**Outbound**:
```
[0:2]  XOR seed (htons, cleartext)
[2:4]  command_type (htons): 0=hello, 1=data, 2=keepalive
[4:6]  client_session_id (htons)
[6:8]  sequence_id (htons)
[8:]   payload (data cmd only)
```

**Inbound**:
```
[0:2]  XOR seed
[2:4]  command_type: 0=hello_ack, 1=data, 2=reset
[4:8]  session/sequence IDs
[8:]   payload
```

### Request Types
| Type | State | Description |
|------|-------|-------------|
| 0 (hello) | 4 | Initial handshake with random a-zA-Z padding (0-31 bytes) |
| 1 (data) | 5 | Data transfer with sequence tracking |
| 2 (keepalive) | 6 | Minimal header-only packet |

## Proxy Support

| Type | String | Description |
|------|--------|-------------|
| 1 | `socks` | SOCKS proxy |
| 2 | `socks` | SOCKS proxy (alt) |
| 3 | `http` | HTTP proxy |

Format: `%s=%s:%d` (e.g., `socks=proxyhost:1080`)

Proxy authentication: On HTTP 407, sets `INTERNET_OPTION_PROXY_USERNAME` (43) and `INTERNET_OPTION_PROXY_PASSWORD` (44), retries up to 3 times.

## Connection State Machine

| State | Name | Description |
|-------|------|-------------|
| 0 | UNINITIALIZED | Default |
| 1 | INITIALIZED | Buffers allocated |
| 3 | CREATED | Object allocated |
| 4 | CONNECTING | Hello sent, awaiting session_id |
| 5 | CONNECTED | Data transfer active |
| 6 | SHUTTING_DOWN | Graceful shutdown |
| 7 | CLOSED | Terminal |

## Sequence Buffer Tables

Reliable ordered delivery using circular sequence buffers (capacity 16 entries, chunk size 4096 bytes, max data 1460 bytes matching TCP MSS). Keyed by 16-bit sequence number.

## Thread Architecture

- **Transport Manager Poll Thread**: Single global, 10ms tick, iterates all registered connections
- **Per-Connection Worker Thread**: Created by vtbl_connect, calls http_do_request in loop, retries 3x on failure
- **Synchronization**: Per-connection CRITICAL_SECTION + Event objects for send/recv

## Encrypted Strings (17 total)

| Address | Decrypted | Used For |
|---------|-----------|----------|
| 0x180004158 | `HTTP` | Protocol name |
| 0x180004160 | `kernel32.dll` | Module for exports |
| 0x180004170 | `msvcrt.dll` | CRT functions |
| 0x180004180 | `memcpy` | Memory copy |
| 0x180004190 | `memset` | Memory init |
| 0x1800041A0 | `socks` | Proxy type 1 |
| 0x1800041B0 | `socks` | Proxy type 2 |
| 0x1800041C0 | `http` | Proxy type 3 |
| 0x1800041C8 | `%s=%s:%d` | Proxy format |
| 0x1800041D4 | `*/*` | Accept header |
| 0x1800041DC | `/` | Request path |
| 0x1800041E8 | `POST` | HTTP method |
| 0x1800041F0 | `Content-Length: %d` | Header format |
| 0x180004208 | `atoi` | Status parsing |
| 0x180004218 | `lstrcpyW` | String ops |
| 0x180004228 | `lstrlenW` | String ops |

## Detailed Function Reference

All 42 functions in the HTTP plugin, grouped by category. Every function has been fully renamed and annotated in the IDB (idasql port 8205).

---

### API Resolution / Import Helpers

#### resolve_api_by_hash (0x180001778, 241 bytes)

PEB-walking API hash resolver using the ROR8-XOR algorithm. Walks `NtCurrentPeb()->Ldr->InLoadOrderModuleList` to find `kernel32.dll` by module name hash `0xFD5866E1`. For each module, computes the hash by lowercasing each character (OR `0x20`), adding to a ROR8 accumulator, and XORing with `0x7C35D9A3`. Once kernel32 is found, parses its PE export directory, iterates `NumberOfNames` entries, and hashes each export name with the same algorithm. When a hash matches the input parameter, resolves the address via `AddressOfNameOrdinals` and `AddressOfFunctions`. Returns the resolved function pointer, or NULL if not found. This 241-byte function is the foundation of all dynamic API resolution in the plugin, completely avoiding static imports.

#### resolve_kernel32_export (0x18000186C, 159 bytes)

Resolves an API export from `kernel32.dll` by name string. Lazily loads `kernel32.dll` by first decrypting the encrypted string `enc_kernel32_dll` via `decrypt_string`, converting to ANSI via `wstr_to_ansi`, then calling `LoadLibraryA` (resolved via hash `0xBDAF3F46`) to get the module handle. Caches the handle in `g_pfnkernel32_dll_2`. Then calls `GetProcAddress` (resolved via hash `0xA17DA4C7`) with the kernel32 handle and the caller-provided export name string. Returns the resolved function pointer. Both `LoadLibraryA` and `GetProcAddress` are themselves resolved via the PEB hash walker, so no static imports are needed. The kernel32 handle is cached across calls so the `LoadLibrary` is only done once.

#### resolve_msvcrt_export (0x180001C04, 159 bytes)

Resolves an API export from `msvcrt.dll` by name string, analogous to `resolve_kernel32_export` but targeting the C runtime library. Lazily loads `msvcrt.dll` by decrypting the string `enc_msvcrt_dll`, converting to ANSI, and calling `LoadLibraryA` (resolved via PEB hash `0xBDAF3F46`). Caches the module handle in `g_pfnmsvcrt_dll`. Then calls `GetProcAddress` (PEB hash `0xA17DA4C7`) with the msvcrt handle and the caller's export name string. Returns the resolved function pointer. Used to resolve `memcpy`, `memset`, and `atoi` from the C runtime. The msvcrt handle is cached so `LoadLibraryA` is only called once regardless of how many CRT functions are resolved.

---

### Plugin Protocol / Dispatch

#### DllEntryPoint (0x18000157C, 396 bytes)

DLL entry point implementing the ScatterBrain plugin command protocol via extended `fdwReason` values. `fdwReason=1`: populates the 6-entry `sb_transport_vtable_t` with `vtbl_create_connection`/`connect`/`send`/`recv`/`shutdown`/`close`. `fdwReason=100`: calls `WSAStartup(2,1)`, initializes the transport manager, and spawns the poll thread. `fdwReason=101`: signals poll thread exit, waits INFINITE, frees connection table and manager. `fdwReason=102`: writes version 201 to `*(DWORD*)lpReserved`. `fdwReason=103`: decrypts `enc_HTTP`, copies plugin name. `fdwReason=104`: stores `&g_plugin_ctx` into `*(QWORD*)lpReserved`. Always returns TRUE. This is the sole communication interface between the inner PE framework and the HTTP plugin.

---

### Transport Manager

#### get_transport_manager (0x180001000, 116 bytes)

Singleton accessor for the global transport manager object. Allocates a 72-byte structure via `sb_LocalAlloc` on first call, initializing it with a critical section (`InitializeCriticalSection` at offset +0), zero-filled connection tracking fields, and a `QueryPerformanceCounter` seed at offset +56. Calls `conn_table_grow(mgr, 1)` to allocate the initial connection slot array (pointer at offset +40), with capacity stored at offset +52 and active count at offset +48. The poll thread handle is stored at offset +64, set to zero initially. On subsequent calls, returns the cached `g_transport_mgr` pointer without re-initialization. Returns the transport manager pointer or NULL on allocation failure. This is the central singleton that all HTTP connections register with.

#### transport_manager_poll_thread (0x18000190C, 275 bytes)

Background polling thread for the transport manager that periodically services all registered connections. Loops continuously while the manager's thread handle at offset +64 is non-null (the exit signal). In each iteration, acquires the manager's critical section, iterates over all slots (0 to capacity at offset +52). For each non-null connection: increments its refcount at offset +36 (preventing destruction during callback), releases the manager lock, acquires the connection's own lock at offset +88, calls the connection's poll callback at offset +64 if non-null, releases the connection lock, re-acquires the manager lock, and decrements the refcount. If the refcount reaches zero, invokes the destructor at offset +72 and clears the slot. After processing all slots, releases the manager lock and sleeps 10ms. Returns 0 when the exit signal (null thread handle) is detected.

#### transport_manager_register_conn (0x180001A20, 224 bytes)

Registers a new connection in the transport manager's slot table. Loops acquiring the manager's critical section and searching for a free slot. If no free slot is found among the current capacity (offset +52), calls `conn_table_grow` to double the table size, releases the lock, and retries. The search starts from the base index at offset +56 and scans linearly. When a free slot (null pointer) is found, stores the connection pointer, sets the connection's slot index at offset +40 to the absolute index (base + slot), initializes the connection's refcount at offset +36 to 1, increments the manager's active count at offset +48, releases the lock, and returns 0. Returns error 8 (`ERROR_NOT_ENOUGH_MEMORY`) if `conn_table_grow` fails. This function is called from `http_conn_setup` during connection creation.

#### conn_table_grow (0x180001B00, 138 bytes)

Grows the transport manager's connection slot table by the specified number of additional slots. Calculates the new total as current capacity (offset +52) plus the requested growth, capping at `0xFFFF` (65535) entries and returning error 8 (`ERROR_NOT_ENOUGH_MEMORY`) if exceeded. Allocates `new_total * 8` bytes via `sb_LocalAlloc` (using `saturated_mul` to avoid integer overflow), copies the existing table via `sb_memcpy`, frees the old table via `sb_LocalFree`, then updates the capacity at offset +52 and the table pointer at offset +40. Returns 0 on success. The function preserves existing entries during reallocation. Called from `transport_manager_register_conn` when no free slots are available, typically doubling the table size.

---

### Transport Vtable Functions

#### vtbl_create_connection (0x180001074, 216 bytes)

Vtable slot +0x00 (`sb_transport_vtable_t.dispatch_handler`): creates a new HTTP connection object. Rejects non-zero `param2` with error 50 (invalid parameter). Allocates a 4448-byte connection context via `sb_LocalAlloc`, then calls `http_conn_init` to zero-fill and configure default fields. Sets the destructor callback at offset +72 to `http_conn_destructor`, and the protocol type at offset +0 to 3 (HTTP). Creates an event object via `CreateEvent` stored at offset +4432, with a zero retry counter at +4440. If the connection's error flag at offset +256 is already set, returns error 5023 (not initialized). Otherwise calls `http_conn_setup` to register with the transport manager and allocate sequence buffer tables. On setup failure, closes the event handle, calls `http_conn_cleanup` to free sub-allocations, frees the context block, and returns the error code. On success, stores the connection pointer into `*this_ptr` and returns 0.

#### vtbl_connect (0x18000114C, 186 bytes)

Vtable slot +0x08 (`sb_transport_vtable_t.main_loop`): initiates the HTTP connection by validating state and launching the worker thread. Checks that the connection state at offset +256 equals 1 (initialized), returning error 5023 if not. Validates that the protocol version at `param1+2` is either 201 (HTTP) or 204 (HTTPS), returning error 87 (invalid parameter) otherwise. Copies 4120 bytes of connection configuration from `param1` into the connection context at offset +304 via `sb_memcpy` -- this includes the target host, port (offset +304), protocol variant (offset +306), proxy port (offset +308), proxy type (offset +310), and proxy/auth credentials. Sets state to 4 (connecting) and spawns `http_worker_thread` via `CreateThread`, storing the thread handle at offset +4424. Busy-waits with 100ms sleeps until state changes from 4. Returns 0 on success (state == 5), or `0x274D` (10061, connection refused) if state is not 5.

#### vtbl_send (0x180001208, 279 bytes)

Vtable slot +0x10 (`sb_transport_vtable_t.open_channel`): queues outbound data for HTTP POST transmission. Acquires the critical section at offset +88. If state != 5 (connected), returns 5023. If send already pending (offset +160 non-null), returns 170 (busy). Populates the send descriptor: buffer at +176, total size at +184, bytes consumed at +188, bytes written at +192, MSS 1460 at +196. Signals the send event via `SetEvent` on handle at +168, stores event pointer at +160. Calls `http_conn_flush_send` to drain data into sequence buffers. Releases lock, waits on event with caller timeout via `WaitForSingleObject`. Re-acquires to harvest: stores bytes transferred into `*dw_arg3`, captures return code from +196, clears pending pointer. Returns 0 on success or error from flush.

#### vtbl_recv (0x180001320, 279 bytes)

Vtable slot +0x18 (`sb_transport_vtable_t.close_channel`): queues a receive request and blocks until C2 response data arrives. Acquires critical section at +88. If state != 5, returns 5023. If recv pending (+200 non-null), returns 170. Populates recv descriptor: buffer at +216, max size at +224, bytes read at +228, received at +232, MSS 1460 at +236. Signals recv event at +208, stores event at +200, calls `http_conn_flush_recv` to drain buffered inbound data. Releases lock, waits on event with timeout. Re-acquires to harvest: copies bytes received into `*dw_arg3`, reads error from +236, clears pending recv pointer. Symmetric with `vtbl_send` using offsets +200-236 vs +160-196.

#### vtbl_shutdown (0x180001438, 59 bytes)

Vtable slot +0x20 (`sb_transport_vtable_t.read_channel` / shutdown): signals a graceful connection error to terminate the HTTP session. Acquires the connection's critical section at offset +88, then calls `http_conn_signal_error` with Winsock error code 10053 (`WSAECONNABORTED`), which transitions state from 5 (connected) to 6 (shutting down) and wakes any pending send/recv waiters with the error code. Releases the critical section and returns 0. This is the clean shutdown path -- it does not close handles or free memory, leaving that to `vtbl_close`. The function is minimal (59 bytes) and always succeeds.

#### vtbl_close (0x180001474, 263 bytes)

Vtable slot +0x28 (`sb_transport_vtable_t.write_channel` / close): performs full connection teardown including thread termination, resource cleanup, and deregistration from the transport manager. First busy-waits up to 60 seconds (60 iterations, 1000ms sleep) for state to leave 6 (shutting down). If a worker thread handle exists at offset +4424, signals the event at +4432 via `SetEvent`, waits on the thread with INFINITE timeout, closes the thread handle, and nulls it. Acquires the critical section, sets state to 7 (closed), calls `http_conn_signal_error(10053)` to wake any remaining waiters, then releases. Retrieves the transport manager singleton, acquires its lock, looks up this connection by its slot index (offset +40 minus the manager's base index at +56), and if the refcount at +36 drops to zero, invokes the destructor callback at offset +72, nulls the slot, and decrements the manager's active count at +48. Releases the manager lock and returns 0.

---

### WinInet HTTP Operations

#### http_do_request (0x180002718, 2553 bytes)

Core HTTP request handler and the largest function in the plugin (2553 bytes). Performs a full WinInet POST transaction with UA spoofing, proxy support, SSL bypass, and rolling XOR encryption. Setup phase: reads computer name via `GetComputerNameA`, builds the User-Agent string with the random suffix from offset +260. Opens an Internet session via `InternetOpenA` with optional SOCKS4/5/HTTP proxy from the connection config at offsets +1336/+308/+310. Connects via `InternetConnectA` to the host at +312, port +304. Opens a POST request to `/` via `HttpOpenRequestA`. For HTTPS (proto 204): bypasses certificate validation by ORing `SECURITY_FLAGS` with `0xF380` (ignore CA/date/CN/revocation). Timeouts: connect=30s, send/recv=90s. Request loop: builds payload per state (4=hello, 5=data, 6=keepalive). Applies rolling XOR cipher (key = `0x77920000 * k - 0x4EDC886E * HI(k) - 0x7916409E`). Adds `Content-Length`, sends via `HttpSendRequestEx` + `HttpEndRequestA`. Checks status 407 for proxy auth retry (up to 8x). Reads response via `InternetReadFile`, decrypts with reverse XOR. Dispatches: type 0=handshake (state->5), type 1=data, type 2=disconnect.

#### http_worker_thread (0x180002688, 142 bytes)

Worker thread entry point that drives the HTTP request/response loop for a single connection. Zeros the retry counter at offset +4444, then enters a loop calling `http_do_request` to perform one full HTTP POST transaction (send data, receive response). If `http_do_request` returns 0 (success), the loop continues. On failure, checks if state is still 5 (connected) and the retry counter has not exceeded 3 attempts; if retries remain, sleeps 1000ms and loops. After exiting the loop (either success, disconnect, or retry exhaustion), acquires the connection lock, sets state to 7 (closed), calls `http_conn_signal_error` with error 10054 (`WSAECONNRESET`) to wake any pending send/recv waiters, and releases the lock. Returns the last error code from `http_do_request`. This thread is spawned by `vtbl_connect` and runs for the lifetime of the connection.

#### build_hello_request (0x180003114, 291 bytes)

Constructs the initial hello/handshake request packet for the HTTP C2 protocol. The packet header consists of 8 bytes: message type 0 (hello) encoded via `htons` at offset 0, the connection's local port ID from offset +40 at bytes 4-5, and the session cookie from offset +42 at bytes 2-3. After the fixed header, appends a random-length padding blob (0 to 31 bytes, determined by PRNG): generates pseudo-random characters using `QueryPerformanceCounter` seeds and the IMUL PRNG (multiplier `-1446266551`, addend `-764667742`), producing lowercase letters (a-z) and digits via mod `0x34` mapping. Uses `iobuf_reset` to clear the output buffer, then `iobuf_append` to write the 8-byte header followed by the random padding. Returns 0 on success or error 8 (allocation failure). The random padding varies packet sizes to defeat traffic analysis and IDS signatures.

#### build_data_request (0x180003238, 278 bytes)

Constructs a data transfer request packet for the HTTP C2 protocol's connected state. If the connection state at offset +256 is not 5 (connected), falls through to `build_keepalive_request` instead. The data packet header is 12 bytes: message type 1 (data) via `htons`, local port at +40, session cookie at +42, the next send sequence number (recv table offset +128, next-expected +1), and the current receive ACK sequence from the send table (offset +136, high-water at +18). Looks up the next outbound sequence entry from the recv table at offset +128 and increments its send-count flag at +8 to mark it as in-flight. Uses `iobuf_reset` and `iobuf_append` to write the 12-byte header, then appends the entry's data payload. Returns 0 on success, or the error from iobuf operations. If no data entry exists, returns 0 with just the header (no payload). This implements the reliable data transfer layer, piggybacking ACK numbers on every data packet.

#### build_keepalive_request (0x180003350, 102 bytes)

Constructs a keepalive/heartbeat request packet for the HTTP C2 protocol when no data is pending. The keepalive packet is exactly 8 bytes: message type 2 (keepalive) encoded via `htons` at offset 0, the connection's local port ID from offset +40 at bytes 4-5, and the session cookie from offset +42 at bytes 2-3. Uses `iobuf_reset` to clear the output buffer, then `iobuf_append` to write the 8-byte header. Returns 0 on success or the error code from the iobuf operations. This 102-byte function is the simplest of the three packet builders and is called from `build_data_request` when state is not 5, and directly from `http_do_request` when state is 6 (shutting down). The keepalive maintains the HTTP session and allows the server to send data even when the client has nothing to transmit.

#### process_data_response (0x1800033B8, 309 bytes)

Processes inbound data responses (type 1) from the C2 server. Validates state is 5 or 6. Parses header: extracts connection ID pair from words 2-3 via `ntohs`, verifies match against stored values at +40. Checks type at word 1 equals 1. Extracts server send sequence (word 4) and ACK (word 5). Validates server sequence is exactly one ahead of last received (offset +136 at +18). Validates ACK within client send window `[current, current+1]`. Frees acknowledged send entry via `seqbuf_table_free_entry` on send table (+128). Calls `http_conn_flush_recv` to deliver queued data. If payload exists (size > 12), allocates recv table entry (+136), copies payload after 12-byte header, calls `http_conn_flush_send`. Returns 0.

---

### SSL / Certificate Bypass

Certificate bypass is handled inline within `http_do_request` (0x180002718). After `HttpOpenRequestA`, the function queries `INTERNET_OPTION_SECURITY_FLAGS` (option 31), ORs in `0xF380` to set all certificate-ignore flags, and writes the modified flags back via `InternetSetOptionW`. The bitmask `0xF380` covers: unknown CA, wrong usage, CN name mismatch, date invalid, and revocation check bypass. No separate function exists for this logic.

---

### User-Agent Spoofing

User-Agent spoofing is also handled inline within `http_do_request`. The function calls `ObtainUserAgentString(0, buf, &size)` from `urlmon.dll` to retrieve the system's default browser User-Agent string (typically Internet Explorer from the registry), making C2 traffic appear as legitimate browsing. A 36-byte pseudo-random suffix (generated during `http_conn_init`) is appended to the UA for fingerprint evasion.

---

### Connection Lifecycle

#### http_conn_init (0x180001EF0, 524 bytes)

Initializes a 4448-byte HTTP connection context. Zeros protocol state, slot/refcount, destructor, poll callback, send/recv pending pointers. Initializes the critical section at offset +88. Creates manual-reset events at +168 (send) and +208 (recv). Clears seqbuf table pointers at +128/+136. Resolves `memset` from `msvcrt.dll`, zeros PRNG state at +4 and +20. Defaults: keepalive at +284=1, timeout +288=90000ms, retry +292=10000ms. Generates a 36-byte pseudo-random User-Agent suffix at +260 using `QueryPerformanceCounter`, `GetTickCount`, `GetSystemTimeAsFileTime`, and an IMUL PRNG (multiplier `-1446266551`, addend `-764667742`). Characters drawn from `a-z/0-9` (mod `0x34`). This suffix is appended to User-Agent headers for fingerprint evasion.

#### http_conn_setup (0x18000222C, 174 bytes)

Registers the HTTP connection with the transport manager and allocates the send/receive sequence buffer tables. Retrieves the transport manager singleton via `get_transport_manager` and calls `transport_manager_register_conn` to insert this connection into the slot table. Configures buffer parameters: window size at +240=1, max segments at +244=16, send buffer size at +248=4096, recv buffer size at +252=4096. Allocates two 40-byte `seqbuf_table` structures via `sb_LocalAlloc` and initializes each with `seqbuf_table_init` using 16 slots (matching +244). Stores the send table at offset +128 and recv table at offset +136. If either allocation fails, returns error 8 (`ERROR_NOT_ENOUGH_MEMORY`). On success, transitions state at offset +256 to 1 (initialized) and returns 0. This is called from `vtbl_create_connection` after `http_conn_init`.

#### http_conn_cleanup (0x1800020FC, 304 bytes)

Cleans up all dynamically-allocated sub-resources of an HTTP connection context without freeing the context itself. Closes the send and receive event handles at offsets +168 and +208 via `CloseHandle`. For each of the two sequence buffer tables (send at offset +128, recv at offset +136): iterates all slots in the table, freeing each entry's data buffer (offset +32) and the entry structure itself via `sb_LocalFree`, then frees the slot array and the table structure, nulling the pointer. Frees the auxiliary IO buffers at offsets +144 (send staging) and +152 (recv staging) if non-null. Finally, deletes the critical section at offset +88 via `DeleteCriticalSection`. This function is called from `http_conn_destructor` and from `vtbl_create_connection` on setup failure, ensuring no resource leaks.

#### http_conn_destructor (0x180002654, 51 bytes)

Destructor callback for HTTP connection objects, invoked when the reference count drops to zero in the transport manager's poll thread or close handler. Performs a null-safety check on the input pointer. If non-null, closes the event handle at offset +4432 via `CloseHandle`, calls `http_conn_cleanup` to free all sub-resources (sequence buffer tables, event handles, critical section, IO buffers), then frees the 4448-byte connection context itself via `sb_LocalFree`. Returns 0. This 51-byte function is stored as a callback pointer at offset +72 of each connection context, registered during `vtbl_create_connection`.

#### http_conn_signal_error (0x180002568, 235 bytes)

Signals an error condition on an HTTP connection, waking both pending send and receive waiters with the specified Winsock error code. First transitions the connection state: if currently 5 (connected), moves to 6 (error/shutting down); otherwise preserves the current state. Then checks the pending send descriptor at offset +160: if non-null, writes the error code into its error field (offset +28), zeros the transferred count (offset +20), and signals the waiter's event via `SetEvent`, then clears the pending pointer. Performs the identical operation on the pending recv descriptor at offset +200. Common error codes used: 10053 (`WSAECONNABORTED`) for graceful shutdown, 10054 (`WSAECONNRESET`) for unexpected termination. Returns 0.

---

### Sequence Buffer System

#### seqbuf_table_init (0x180001CA4, 105 bytes)

Initializes a sequence buffer table structure used for managing ordered, segmented data transfers. Takes a pointer to a 40-byte table structure and an initial slot capacity. Stores the capacity at offset +12, zeros the active entry count at offset +8, and allocates a pointer array of `capacity * 8` bytes via `sb_LocalAlloc`, storing it at offset +0. Zero-fills all slot pointers in the array. Initializes the sequence tracking fields: next expected sequence at +16 to 0, base sequence at +20 to 0, and cumulative byte counters at +24 and +32 to 0. Returns the initialized structure pointer. These tables implement a sliding-window sequenced buffer system similar to TCP sequence numbering, enabling reliable ordered data delivery over the unreliable HTTP POST request/response pairs.

#### seqbuf_table_alloc_entry (0x180001D10, 299 bytes)

Allocates a sequence buffer entry at the given sequence number. Validates the sequence is after next-expected (offset +18), within window (base at +16 plus capacity at +12), and the hash slot (`seq % capacity`) is empty. Allocates a 40-byte entry: seq at +0, send offset +8=0, remaining at +16, capacity at +20, data buffer at +32. Inserts into slot. Updates high-water mark at +20 if needed. Advances next-expected contiguous sequence at +18 by scanning forward. Returns entry pointer on success, 0 on failure. Implements sliding-window sequenced buffering for reliable ordered data delivery over HTTP POST pairs.

#### seqbuf_table_free_entry (0x180001E3C, 178 bytes)

Frees a sequence buffer table entry at the specified sequence number, accumulating its byte counts into the table's running totals. Computes the hash slot as `seq % capacity` and verifies the slot is occupied and the stored sequence number matches; returns error 4312 if not found. Adds the entry's remaining byte count (offset +16) to the table's cumulative counters at offsets +24 and +32. Frees the entry's data buffer (offset +32) and the entry structure itself via `sb_LocalFree`. Nulls the hash slot. Decrements the active count at offset +8. Then advances the table's base sequence pointer at offset +16 by scanning forward while consecutive slots are empty, up to the high-water mark at +18. Returns 0 on success. This is the counterpart to `seqbuf_table_alloc_entry` and is called when a sequence segment has been fully consumed by the receiver.

---

### Data Flow / Flush

#### http_conn_flush_send (0x1800022DC, 125 bytes)

Checks for pending outbound data and initiates a copy from the send request descriptor into the outbound sequence buffer table. If no send operation is pending (offset +160 is null), returns immediately. Otherwise calls `http_conn_copy_recv_data` (which, despite its name, handles the send-side sequence buffer at offset +136) to transfer data from the caller's buffer into sequence-numbered segments. If the copy returns error 10035 (`WSAEWOULDBLOCK`), treats it as non-fatal (ret=0). If any other error occurs or all data has been consumed (consumed count at offset +24 > 0), signals completion: writes the consumed count into the descriptor's result field at +20, stores the error code at +28, signals the waiter's event via `SetEvent`, and clears the pending pointer at offset +160. Returns 0. Called from the send path (`vtbl_send`) and from `http_worker_thread` during data exchanges.

#### http_conn_flush_recv (0x18000235C, 339 bytes)

Drains buffered inbound data from the recv sequence buffer table (offset +128) into a pending receive request. Returns immediately if no recv pending (offset +200 null). Loops while caller buffer has room (consumed at +24 < requested at +16). Each iteration looks up the next-expected sequence entry by hash slot. If the slot is empty, allocates a new entry via `seqbuf_table_alloc_entry` with buffer sizes from +248/+252. Copies data via `sb_memcpy`, advancing both entry consumed offset and descriptor consumed count. On completion or window exhaustion (error 8), signals waiter: writes consumed count and error into descriptor, signals event, clears offset +200. Returns 0.

#### http_conn_copy_recv_data (0x1800024B0, 181 bytes)

Copies data from the outbound sequence buffer table (offset +136) into a send request descriptor. Looks up the next unsent sequence entry by computing: next-expected sequence (offset +16) plus 1, then hashing into the table's slot array. If the slot is empty or the sequence number mismatches, returns error 10035 (`WSAEWOULDBLOCK`), indicating no data is ready yet. Otherwise calculates the copyable byte count as the minimum of the entry's remaining data (capacity - consumed) and the descriptor's remaining space (requested - transferred). Copies via `sb_memcpy` from the entry buffer at its current offset into the descriptor buffer at its current offset. Advances both consumed counters. If the entry is fully drained (consumed >= capacity), calls `seqbuf_table_free_entry` to release it and advance the table's sequence window. Returns 0 on success. Despite the name suggesting receive, this function serves the send path by dequeuing sequenced outbound data.

---

### IO Buffer Management

#### iobuf_reset (0x1800034F0, 47 bytes)

Resets an IO buffer structure to empty state, optionally reallocating the backing memory. The iobuf structure has: used count at +0, capacity at +4, write cursor at +8, and buffer pointer at +16. If the capacity (offset +4) is negative (interpreted as signed), calls `iobuf_realloc(buf, 0)` to release and reallocate the buffer; returns the error if reallocation fails. Then zeros the used count at +0, and if the write cursor at +8 is positive, zeros it as well. Returns 0 on success. Called before constructing outbound packets (`build_hello_request`, `build_data_request`, `build_keepalive_request`) and before reading HTTP response bodies in `http_do_request`.

#### iobuf_append (0x180003520, 99 bytes)

Appends data to an IO buffer, automatically growing the backing allocation if needed. Calculates the required size as current write cursor (offset +8) plus the new data length. If this exceeds the current capacity (offset +4), calls `iobuf_realloc` with `new_size + 4096` to grow with headroom, returning the error on allocation failure. Copies the data via `sb_memcpy` to the buffer at the current write position (buffer pointer at +16 plus cursor at +8). Advances the write cursor by the appended length. If the cursor exceeds the used count at +0, updates the used count. Returns 0 on success. This 99-byte function is the primary method for building outbound packets incrementally and for accumulating HTTP response body chunks during `InternetReadFile` loops.

#### iobuf_realloc (0x180003584, 96 bytes)

Reallocates the backing memory of an IO buffer to a new size, preserving existing content. Allocates a new buffer of the requested size via `sb_LocalAlloc`. If allocation fails, returns error 8 (`ERROR_NOT_ENOUGH_MEMORY`). Copies the current used data (offset +0 bytes) from the old buffer (offset +16) to the new buffer via `sb_memcpy`. If an old buffer exists, frees it via `sb_LocalFree`. Stores the new buffer pointer at offset +16 and the new capacity at offset +4. Returns 0 on success. Called from `iobuf_append` when the buffer needs to grow, and from `iobuf_reset` when the buffer is in a degraded state (negative capacity).

---

### String / Crypto Helpers

#### decrypt_string (0x1800035E4, 185 bytes)

Decrypts an encrypted string blob using the ScatterBrain polynomial XOR cipher. Allocates a 4096-byte temp buffer via `sb_LocalAlloc`. Reads a 2-byte key seed from the encrypted blob (LE WORD). Iterates encrypted bytes from offset 2, XORing each with the low byte of the running key. Key updated per byte: `key = -42860544*key - 135791246*HIWORD(key) - 1043215206`. Stops on null byte or after 4090 bytes. Initializes output `sb_wstr_t` (ANSI ptr at +0, len at +8, wide ptr at +16, wide len at +24) to zeros. Calls `ansi_to_wstr` to convert decrypted ANSI to wide via `MultiByteToWideChar(CP_UTF8)`. Frees temp buffer. Returns output structure pointer. Called throughout the plugin to decrypt API names, protocol strings, and format specifiers from `.rdata`.

#### wstr_free (0x1800036A0, 59 bytes)

Frees both the ANSI and wide-string buffers held by an `sb_wstr_t` structure. The structure layout is: ANSI buffer pointer at +0, ANSI length at +8, reserved at +12, wide buffer pointer at +16, wide length at +24. If the ANSI pointer at +0 is non-null, frees it via `sb_LocalFree` and zeros both the pointer and the length field at +8. Then checks the wide pointer at +16; if non-null, frees it and zeros the pointer and length at +24. Called after every `decrypt_string` usage to release the temporary string memory. The dual-buffer design reflects the string lifecycle: `decrypt_string` produces ANSI text, `ansi_to_wstr` converts to wide, and callers may use either form before freeing both.

#### wstr_to_ansi (0x1800036DC, 188 bytes)

Converts the wide-string portion of an `sb_wstr_t` to ANSI encoding via `WideCharToMultiByte`. Lazily resolves `WideCharToMultiByte` via `resolve_api_by_hash` with hash `0x98ED91EE`, caching the pointer in `g_pfnUnk_50A0`. Calls `WideCharToMultiByte` with codepage 0 (`CP_ACP`), no flags, the wide buffer from offset +16, its length from offset +24, and NULL output to compute the required ANSI buffer size. Allocates the computed size via `sb_LocalAlloc`, then calls `WideCharToMultiByte` again to perform the actual conversion. If an existing ANSI buffer is present at offset +0, frees it first. Stores the new ANSI pointer at +0 and length at +8. Returns the ANSI buffer pointer on success, or 0 on allocation failure. This function is the primary mechanism for converting decrypted wide strings to ANSI format for use with ANSI Win32 APIs (`InternetOpenA`, `HttpOpenRequestA`, etc.).

#### ansi_to_wstr (0x180003798, 233 bytes)

Converts an ANSI string to a wide (UTF-16) string using `MultiByteToWideChar` with codepage 65001 (UTF-8). Lazily resolves `MultiByteToWideChar` via `resolve_api_by_hash` with hash `0xB8E98CF8`, caching in `g_pfnUnk_50A8`. First calls `MultiByteToWideChar` with length -1 (null-terminated) and NULL output to compute the required wide buffer size. Allocates `size * 2` bytes via `sb_LocalAlloc` (using `saturated_mul` for overflow protection). Calls `MultiByteToWideChar` again to perform the conversion. Frees any pre-existing ANSI buffer at offset +0 and wide buffer at offset +16 of the `sb_wstr_t` structure before storing the new wide pointer at +16 and character count at +24. Returns 0 on success or 8 on allocation failure. This is the reverse of `wstr_to_ansi` and is used by `decrypt_string` to convert decrypted ANSI blobs to wide strings.

#### wstr_set_from_wchar (0x180003884, 299 bytes)

Sets an `sb_wstr_t` structure's wide-string content from a raw WCHAR pointer, measuring and copying the string. Lazily resolves `lstrlenW` from `kernel32.dll` by decrypting `enc_lstrlenW`, converting to ANSI, and calling `resolve_kernel32_export`. Caches the pointer in `g_pfnlstrlenW`. Measures the input string length via `lstrlenW`, adds 1 for the null terminator, and allocates `(length+1)*2` bytes via `sb_LocalAlloc` with `saturated_mul` for overflow protection. Then resolves `lstrcpyW` from `kernel32.dll` (decrypting `enc_lstrcpyW`, caching in `g_pfnlstrcpyW`) and copies the input string into the allocated buffer. Frees any pre-existing ANSI buffer at offset +0 and wide buffer at offset +16 before storing the new wide pointer at +16 and character count at +24. Returns 0 on success or 8 (`ERROR_NOT_ENOUGH_MEMORY`) on allocation failure. Used in `http_do_request` to set the User-Agent string from a constructed wide-character buffer.

---

### Utility / Memory

#### sb_LocalAlloc (0x180001708, 54 bytes)

Wrapper around the Win32 `LocalAlloc` API that lazily resolves the function pointer on first call. Checks the cached global `g_pfnLocalAlloc`; if NULL, calls `resolve_api_by_hash` with hash `0x95BA18D2` to locate `LocalAlloc` by walking the PEB `InLoadOrderModuleList` and matching export name hashes. Stores the resolved pointer in `g_pfnLocalAlloc` for subsequent calls. Invokes `LocalAlloc` with flags `LPTR` (`0x40` = `LMEM_ZEROINIT | LMEM_FIXED`) and the requested size. Returns the allocated pointer or NULL on failure. This 54-byte function is the sole heap allocator used throughout the HTTP plugin, ensuring all allocations are zero-initialized fixed blocks.

#### sb_LocalFree (0x180001740, 53 bytes)

Wrapper around the Win32 `LocalFree` API with lazy resolution and NULL-safety. If the input pointer is NULL, returns immediately without action. Otherwise checks the cached global `g_pfnLocalFree`; if NULL, resolves it via `resolve_api_by_hash` with hash `0xF336E3E3` by walking PEB exports. Stores the resolved pointer for reuse. Calls `LocalFree` on the provided address to release the memory block. This 53-byte function is the sole deallocation primitive used by the HTTP plugin. The NULL guard prevents double-free or null-free crashes, and the lazy resolution pattern avoids import table entries that would reveal API usage to static analysis.

#### sb_memcpy (0x180001B8C, 120 bytes)

Wrapper around the C runtime `memcpy` function that lazily resolves it from `msvcrt.dll`. Checks the cached global `g_pfnmemcpy`; if NULL, decrypts the string `'memcpy'` from `enc_memcpy` via `decrypt_string`, converts to ANSI via `wstr_to_ansi`, and resolves the export from `msvcrt.dll` via `resolve_msvcrt_export`. Caches the pointer in `g_pfnmemcpy` for future calls. Then invokes `memcpy(dest, src, count)` with the three caller-provided arguments. Returns the destination pointer. Used extensively throughout the plugin for buffer copies, sequence buffer data transfers, and connection config replication. Like all API wrappers in this plugin, it avoids static imports through runtime resolution.
