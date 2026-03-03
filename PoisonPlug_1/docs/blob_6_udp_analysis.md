# Blob 6 — Reliable UDP (RUDP) Transport Plugin ("UDP")

## Summary

| Property | Value |
|----------|-------|
| File | Private archive artifact (available on vetted request) |
| Image Size | 0x9000 (36864 bytes) |
| Entry Point RVA | 0x1828 |
| Functions | 55 (all renamed, zero sub_* remaining) |
| Sections | .text, .rdata, .data2, .data3, .idata |
| Timestamp | 0x58AEBA (2017-02-22/23) |
| idasql Port | 8206 |
| Version (CMD 102) | 202 |
| Plugin Name (CMD 103) | `"UDP"` (encrypted at `0x180005160`) |

## Role

**Custom Reliable UDP (RUDP) protocol stack.** Despite WS2_32 socket imports suggesting TCP, the plugin creates `socket(AF_INET, SOCK_DGRAM, 0)` — **UDP**. The entire reliability layer (sequence numbers, ACKs, selective retransmission, AIMD congestion control, flow control) is implemented in userspace on top of raw UDP datagrams.

## Critical Reclassification

Initially classified as "Raw TCP Transport" based on imports. Deep analysis revealed a full userspace reliable transport protocol over UDP datagrams — this is the most architecturally complex plugin in the suite.

## Imports (21 functions, 2 DLLs)

### KERNEL32.dll (21)
InitializeCriticalSection, DeleteCriticalSection, EnterCriticalSection, LeaveCriticalSection, QueryPerformanceCounter, QueryPerformanceFrequency, CreateThread, GetLastError, WaitForSingleObject, CloseHandle, Sleep, CreateEventW, GetSystemTime, GetCurrentThreadId, GetCurrentProcessId, GetTickCount, ResetEvent, SetEvent, GetProcAddress, LoadLibraryA, lstrcpyW

### WS2_32.dll (14 by ordinal)
WSACleanup, WSAStartup, socket, WSAGetLastError, htons, ntohs, sendto, setsockopt, connect, getsockname, shutdown, closesocket, recvfrom, gethostbyname

## Entry Point: rudp_transport_entry (0x180001828)

| fdwReason | Command | Action |
|-----------|---------|--------|
| 1 | ATTACH | Populates 6-slot vtable at `0x180006010` |
| 100 | START | WSAStartup(0x101) + CreateThread(transport_mgr_worker) |
| 101 | STOP | WaitForSingleObject, cleanup, WSACleanup |
| 102 | VERSION | Returns 202 |
| 103 | NAME | Decrypts plugin config string, copies via lstrcpyW |
| 104 | COOKIE | Returns `&unk_180006008` (state pointer) |

## Vtable (6 slots at `0x180006010`)

| Slot | Address | Name | Purpose |
|------|---------|------|---------|
| 0 | 0x180001224 | `rudp_conn_create` | Allocate 480-byte connection, create UDP socket, set buffers |
| 1 | 0x1800013D4 | `rudp_conn_connect` | Resolve hostname, UDP connect, start handshake |
| 2 | 0x180001478 | `rudp_conn_send` | Queue send, segment data, wait for completion event |
| 3 | 0x180001590 | `rudp_conn_recv` | Queue recv, reassemble segments, wait for completion |
| 4 | 0x1800016A8 | `rudp_conn_abort` | Send 3x RST, signal WSAECONNABORTED |
| 5 | 0x180001710 | `rudp_conn_close` | Graceful close: ref_count, state=7, shutdown, thread join |

## Connection Object (480 bytes)

| Offset | Type | Field |
|--------|------|-------|
| 0 | DWORD | magic/state_class (5) |
| 4 | sockaddr_in | local address |
| 20 | sockaddr_in | remote address |
| 36 | DWORD | ref_count |
| 40 | WORD | local_conn_id (random from QPC+SystemTime+TID+PID) |
| 42 | WORD | remote_conn_id (from SYN-ACK) |
| 48 | QWORD | pfn_sendto -> `rudp_sendto_raw` |
| 64 | QWORD | pfn_tick -> `rudp_tick_timers` |
| 72 | QWORD | pfn_destroy -> `rudp_conn_destroy` |
| 88 | CRITICAL_SECTION | per-connection lock (40 bytes) |
| 128 | QWORD | recv_ring_ptr (128-slot ring buffer) |
| 136 | QWORD | send_ring_ptr (128-slot ring buffer) |
| 168 | HANDLE | send_event (manual-reset) |
| 196 | DWORD | send_mss = 1460 |
| 208 | HANDLE | recv_event (manual-reset) |
| 240 | DWORD | min_window = 2 |
| 244 | DWORD | max_window = 128 |
| 252 | DWORD | max_payload = 1012 (1024 - 12 header) |
| 256 | DWORD | conn_state (1-7) |
| 260 | BYTE[16] | session_token (from SYN) |
| 284 | DWORD | max_retries = 1 |
| 288 | DWORD | timeout_ms = 90000 |
| 292 | DWORD | retry_interval_ms = 10000 |
| 360 | double | cwnd = 2.0 |
| 376 | double | ssthresh = 128.0 |
| 456 | DWORD | rtt_estimate_ms |
| 460 | DWORD | loss_threshold_pct = 10 |
| 464 | QWORD | socket handle |
| 472 | HANDLE | recv_thread |

## Connection State Machine

```
State 1 (INIT)        -> socket created, rings allocated
State 2 (SYN_SENT)    -> connect() on UDP, recv thread spawned
State 4 (SYN_RECV)    -> SYN sent 3x, awaiting response
State 5 (ESTABLISHED) -> SYN-ACK received, data transfer active
State 6 (CLOSING)     -> error signaled, draining
State 7 (CLOSED)      -> terminal, resources freed
```

## RUDP Packet Protocol

### Per-Packet Encryption (PRNG XOR)
Every datagram encrypted with a **third distinct cipher** in the ScatterBrain ecosystem:
```
seed = (uint16_t)QueryPerformanceCounter()
key = seed
for each byte:
    key = 2006056960 * key - 1323075694 * HIWORD(key) - 2031501470
    encrypted[i] = plaintext[i] ^ (key & 0xFF)
prepend htons(seed) as cleartext header
```
16-bit key space — trivially brute-forceable but defeats shallow DPI.

### Packet Types

| Type | Name | Size | Format |
|------|------|------|--------|
| 0 | SYN | 24 bytes | `[type=0, local_id, remote_id=0, session_token[16]]` |
| 1 | SYN-ACK | 8 bytes | `[type=1, local_id, remote_id]` |
| 2 | DATA | 12+ bytes | `[type=2, seq_no, ack_no, payload...]` |
| 3 | ACK | 16+ bytes | `[type=3, seq_no, ack_no, cwnd, timestamp, SACK_bitmap]` |
| 4 | KEEPALIVE | 10 bytes | `[type=4, local_id, remote_id, seq_no]` |
| 5 | EACK | 14+ bytes | `[type=5, seq_no, cwnd, ack_no, SACK_bitmap]` |
| 6 | RST | 8 bytes | `[type=6, local_id, remote_id]` |
| 7 | FIN | 8 bytes | `[type=7, local_id, remote_id]` |

All uint16 fields in network byte order.

### Selective ACK Bitmap
`rudp_encode_sack_bitmap` (0x180002180): One bit per sequence number. Iterates from base_seq+1 through next_seq, packs 8 per byte.
`rudp_decode_sack_bitmap` (0x180002208): Iterates bitmap, calls ring_remove for each set bit. Enables selective retransmission.

## Congestion Control (TCP Reno-like AIMD)

### `rudp_process_ack` (0x180002F14, 1172 bytes) — largest function
1. **Slow Start**: cwnd starts at 2.0, doubles each RTT until ssthresh (128.0)
2. **Congestion Avoidance**: `cwnd += (bytes_acked / cwnd) + aimd_increment * bytes_acked / 50.0`
3. **Multiplicative Decrease on loss**: `cwnd = ssthresh * 0.75`, `ssthresh = cwnd * 0.75`
4. **Loss Detection**: `retransmit_count / total_sent` ratio, triggers at 10%
5. **RTT Estimation**: QPC-based timestamps
6. **Window Clamping**: Always `[min_window(2), max_window(128)]`
7. **Pacing**: Token-bucket credit system

### `rudp_transmit_window` (0x1800036E4, 937 bytes) — transmit pacer
Called every 10ms tick. Iterates send ring, checks pacing credit, sends/retransmits segments. Falls back to keepalive if idle.

## Segment Ring Buffer (per-connection, 2 rings)

```
Header (40 bytes):
  +0x00: QWORD  slots_array (ptr to segment_entry pointers)
  +0x08: DWORD  count (occupied)
  +0x0C: DWORD  capacity (128)
  +0x10: WORD   base_seq (oldest unACKed)
  +0x12: WORD   next_seq (next to send/expected)
  +0x14: WORD   max_seq (highest seen/sent)
  +0x18: QWORD  bytes_pending
  +0x20: QWORD  bytes_consumed
```

Indexed by `seq_no % capacity`. 16-bit sequence numbers with signed subtraction for wrap-around.

## Thread Model

1. **Transport Manager Worker** (`transport_mgr_worker`, 0x180001B18): Single global, `Sleep(10)` loop, calls each connection's `pfn_tick`
2. **Per-Connection Receive Thread** (`rudp_recv_loop`, 0x180004194): Blocking `recvfrom` loop, decrypt + dispatch
3. **Caller threads**: Block on `WaitForSingleObject(event, timeout)` for send/recv completion

## Key Design Decisions

1. **UDP-based reliability in userspace**: Reimplements TCP guarantees over raw datagrams
2. **Triple-send for control packets**: SYN, SYN-ACK, RST, FIN sent 3x for redundancy
3. **Session token authentication**: 16-byte random token in SYN for connection-level auth
4. **MSS 1460**: Matches Ethernet TCP MSS, avoids IP fragmentation
5. **Client-only mode**: No bind/listen/accept — active connections only
6. **Why RUDP for C2?**: UDP less scrutinized by firewalls/IDS, no TCP SYN/ACK pattern, simpler NAT traversal, tunable congestion vs. stealth tradeoff

## Encrypted Strings (7 total)

| Address | Decrypted | Used For |
|---------|-----------|----------|
| 0x180005128 | `ws2_32.dll` | WS2_32 handle for getaddrinfo |
| 0x180005138 | `getaddrinfo` | DNS resolution API |
| 0x180005148 | `freeaddrinfo` | DNS cleanup API |
| 0x180005160 | (config string) | Plugin name/config |
| 0x180005188 | `memset` | CRT function via msvcrt |

## PEB-Resolved APIs (6)

| Hash | API |
|------|-----|
| 0x95E79E52 | LocalAlloc |
| 0xF33A2A63 | LocalFree |
| 0xB8D4BBF8 | MultiByteToWideChar |
| 0x9920726E | WideCharToMultiByte |
| 0xBDA26FE6 | LoadLibraryA |
| 0xA16DC157 | GetProcAddress |

## Detailed Function Reference

All 55 functions in the blob_6 UDP plugin, grouped by functional category. Every function has been renamed from generic `sub_*` stubs; zero unnamed functions remain.

---

### API Resolution

#### resolve_api_by_hash (0x180001A24, 241 bytes)

PEB-based API hash resolver that walks the loaded module list to find exported functions by hash. Uses the InLoadOrderModuleList from the PEB Ldr structure (accessed via NtCurrentPeb). For each loaded module, computes a hash of the module BaseDllName by iterating each wide character, OR-ing with 0x20 for case-insensitive comparison, applying ROR8, and XOR-ing with the magic constant 0x7C35D9A3. Searches specifically for ntdll.dll or kernel32.dll by comparing against hash 0xFD580BA1. Once the target module is found, walks its PE export directory (IMAGE_EXPORT_DIRECTORY) to enumerate exported function names. For each export name, computes the same hash algorithm (without the lowercase OR since export names are ASCII) and compares against the target hash. On match, resolves the function address through the ordinal table and address table. Returns the resolved function pointer, or NULL if no match is found. This is the standard ScatterBrain PEB-walk pattern shared across all plugins.

#### sb_resolve_crt_func (0x180001E94, 159 bytes)

Resolves a CRT function by name from msvcrt.dll. Takes a wide string function name as input. Lazily loads msvcrt.dll on first call by decrypting the DLL name from an encrypted string blob, resolving LoadLibraryW via resolve_api_by_hash (hash 0xBDAA2806), and calling LoadLibraryW to get the module handle. Caches the msvcrt handle in a global. Then lazily resolves GetProcAddress via resolve_api_by_hash (hash 0xA1640377) and caches it. Finally calls GetProcAddress(msvcrt_handle, func_name) to resolve the requested function. Returns the resolved function pointer. Used by sb_memcpy to resolve memcpy and by rudp_conn_init to resolve memset. This two-level resolution (LoadLibrary + GetProcAddress) is the standard ScatterBrain pattern for accessing CRT functions without static imports.

#### resolve_inet_addr (0x180001074, 431 bytes)

Resolves a hostname to an IPv4 address using the Windows DNS API (DnsQuery_A). Takes a connection context, output DWORD pointer for the resolved IP, and an array of up to 4 DNS server addresses. Builds a server list by collecting non-zero entries (max 4 servers). If no servers are specified, returns error 1168 (DNS_ERROR_RECORD_DOES_NOT_EXIST). Lazily loads dnsapi.dll via LoadLibraryW and resolves DnsQuery_A and DnsRecordListFree by decrypting their names from encrypted string blobs. Calls DnsQuery_A with query type DNS_TYPE_A (1) and options 0x40. On success, extracts the IPv4 address from the DNS_RECORD structure at offset +32, verifying the record type is A (1). Returns 0 on success, 127 if API resolution fails, 1804 if record type is not A, or the DNS error code on query failure. Frees DNS records via DnsRecordListFree after extraction.

---

### Plugin Protocol / Dispatch

#### rudp_transport_entry (0x180001828, 396 bytes)

Plugin DllMain entry point implementing the ScatterBrain plugin command protocol. Handles fdwReason dispatch for plugin lifecycle management. fdwReason=1 (SB_CMD_INIT_VTABLE): Populates the global RUDP vtable with six function pointers -- rudp_conn_create, rudp_conn_connect, rudp_conn_send, rudp_conn_recv, rudp_conn_abort, rudp_conn_close -- corresponding to sb_transport_vtable_t slots create/connect/send/recv/abort/close. fdwReason=100 (SB_CMD_SET_FRAMEWORK_CTX): Initializes Winsock via WSAStartup(MAKEWORD(2,2)), creates the transport manager singleton, spawns the transport_mgr_worker thread via CreateThread, and stores the thread handle at transport_mgr offset +64. fdwReason=101 (teardown): Signals the worker thread to stop by setting the thread handle to NULL, waits for it to exit via WaitForSingleObject(INFINITE), closes the handle, frees the transport manager connection array and structure, and calls WSACleanup. fdwReason=102 (SB_CMD_GET_VERSION): Writes the version number 202 to lpReserved. fdwReason=103 (SB_CMD_GET_NAME): Decrypts the plugin name string and copies it to the output buffer via lstrcpyW.

---

### RUDP Core Protocol

#### rudp_conn_create (0x180001224, 431 bytes)

Creates and fully initializes a new RUDP connection object. Allocates a 480-byte connection structure via sb_malloc and calls rudp_conn_init to set up protocol state, PRNG keys, timers, and events. Sets the connection type tag to 5 (RUDP) at offset +0, and installs four function pointers: rudp_sendto_raw at offset +48 (raw UDP send callback), rudp_recvfrom_nop at offset +56 (no-op receive placeholder), rudp_tick_trampoline at offset +64 (timer tick dispatcher), and rudp_conn_destroy at offset +72 (destructor). Allocates two 1024-byte I/O buffers stored at offsets +144 and +152 for receive and send packet buffers. Calls rudp_conn_setup_state to initialize AIMD congestion control parameters, segment ring buffers (send/recv with 128-slot capacity), and register with the transport manager. Creates a UDP socket via WSASocket(AF_INET=2, SOCK_DGRAM=2, 0) at offset +464, configuring it with 128KB send/receive buffers (SO_SNDBUF/SO_RCVBUF=0x20000) and 1-second send/receive timeouts (SO_SNDTIMEO/SO_RCVTIMEO=1000ms). On failure, cleans up all resources.

#### rudp_conn_init (0x180002298, 524 bytes)

Initializes all fields of an RUDP connection structure (480 bytes). Zeroes the type tag (offset +0), reference count area (offset +36), and all function pointer slots (offsets +48..+72). Initializes the connection CRITICAL_SECTION at offset +88. Zeroes the send ring pointer (offset +136), recv ring pointer (offset +128), I/O buffer pointers (offsets +144, +152), pending send/recv operation pointers (offsets +160, +200), cumulative stats (offset +240, +248), and connection state (offset +256, set to 0). Creates two auto-reset events via CreateEvent for send completion (offset +168) and recv completion (offset +208). Resolves and calls memset to zero the local/remote address fields at offsets +4..+20 and +20..+36. Initializes RUDP protocol parameters: minimum window size to 1 segment (offset +284), retransmission timeout to 90000ms (offset +288), and keepalive interval to 10000ms (offset +292). Seeds the per-connection PRNG state using QueryPerformanceCounter, GetTickCount, GetCurrentProcessId, GetCurrentThreadId, and GetSystemTime, XOR-combining all sources for entropy.

#### rudp_conn_setup_state (0x18000294C, 469 bytes)

Initializes the RUDP connection protocol state, AIMD congestion control parameters, and segment ring buffers. Lazily initializes the global performance counter frequency (g_perf_freq_ms) by calling QueryPerformanceFrequency and dividing by 1000 to get millisecond resolution. Records the initial timestamp via QueryPerformanceCounter. Sets up AIMD congestion control state: congestion window (cwnd) at offset +360 initialized to 2.0, slow-start threshold (ssthresh) at offset +376 initialized to 128.0, send credit accumulator at offset +384, flight size tracking at offset +368, and AIMD adjustment factor at offset +392 all zeroed. Initializes all eight timer timestamps (offsets +324..+352 and +400/+404) to the current time. Sets statistical counters: total segments sent at offset +408, total send attempts at offset +416, retransmit counter at offset +424, retransmit+send counter at offset +432, and overflow counters at offset +440/+448 all to zero. Configures protocol constants and initializes send/recv ring buffers with 128-slot capacity.

#### rudp_conn_connect (0x1800013D4, 164 bytes)

Initiates a connection to a remote RUDP peer. Corresponds to sb_transport_vtable_t.open_channel (vtable slot +0x10). Takes the connection object and a connection descriptor containing port (WORD at +0), hostname (wide string at +8), and optional DNS server addresses (DWORDs at +2052). Returns error 10042 (WSAENOPROTOOPT) if the address family field is non-zero, indicating IPv6 which is unsupported. Converts the port to network byte order via htons. Attempts hostname resolution first through resolve_inet_addr using custom DNS servers, falling back to gethostbyname which extracts the IP from h_addr_list[0][0]. On resolution failure, returns the WSAGetLastError code. On success, delegates to rudp_connect_handshake to perform the SYN/SYNACK three-way handshake. Returns 0 on successful connection establishment, or a Winsock error code on failure.

#### rudp_connect_handshake (0x180004334, 354 bytes)

Performs the client-side RUDP connection handshake including socket binding, receiver thread creation, SYN transmission, and handshake completion wait. Takes the connection pointer and a sockaddr_in structure containing the remote address. If in INITIALIZED state (state==1): binds the socket to any local address (INADDR_ANY, port 0) via bind, starts the receive loop thread via CreateThread(rudp_recv_loop), and transitions to LISTENING state (state=2). If bind or thread creation fails, returns the WSAGetLastError code. If in LISTENING state (state==2) or transitioning from INITIALIZED: copies the 16-byte remote address, transitions to SYN_SENT state (state=4), and sends three SYN packets via rudp_send_syn for redundancy. Then enters a polling loop: checks the connection state every 100ms via Sleep(100), up to 100 iterations (total 10 seconds). If the state transitions to ESTABLISHED (state==5) during this wait (triggered by the recv loop thread processing a SYNACK), returns 0. If the timeout expires without establishing, returns 10060 (WSAETIMEDOUT).

#### rudp_dispatch_packet (0x180002B24, 676 bytes)

Main RUDP packet dispatcher that routes incoming decrypted packets to the appropriate handler based on packet type. Takes the connection pointer, packet data, packet size, and sender address (16-byte sockaddr_in). First validates the packet source by checking the connection remote address fields: if the remote address is unset (port and IP are 0), accepts the packet from any source; otherwise verifies the port and IP match exactly. Extracts the packet type via ntohs. Dispatches based on type: Type 0 (SYN) -- if in INITIALIZED state (state==1), extracts the SYN/ACK sequence numbers. If SYN seq is 0 and ACK seq is non-zero, this is a server receiving a client SYN: sets the remote sequence, transitions to ESTABLISHED (state=5), copies the 16-byte PRNG key from the packet into the connection key (offset +260), and sends three SYNACKs for redundancy. Type 1 (SYNACK) -- completes the client handshake by transitioning to ESTABLISHED. Type 2 (DATA) -- delegates to rudp_process_data. Type 3 (ACK) -- delegates to rudp_process_ack. Type 4 (KEEPALIVE) -- responds with rudp_send_nack. Type 5 (EACK) -- delegates to rudp_process_eack. Type 6 (RST) -- transitions to CLOSED (state=7), signals WSAECONNRESET (10054), sends three FINs. Type 7 (FIN) -- transitions to CLOSED, signals WSAECONNRESET.

#### rudp_conn_send (0x180001478, 279 bytes)

Queues application data for reliable transmission over the RUDP connection. Corresponds to sb_transport_vtable_t.write_channel (vtable slot +0x28). Takes the connection object, source buffer pointer, buffer size, output bytes-sent pointer, and a timeout in milliseconds. Acquires the connection critical section and verifies the connection state is ESTABLISHED (state==5); returns 5023 if not connected. Returns error 170 (ERROR_BUSY) if a send operation is already pending. Sets up the send I/O descriptor at offsets +176..+196: stores the buffer pointer, total size, bytes copied so far (zeroed), and MSS of 1460 bytes. Signals the send event via SetEvent and initiates segmentation by calling rudp_complete_send which copies data into send ring segments. Releases the lock, then waits on the send event with the specified timeout via WaitForSingleObject. After the wait, re-acquires the lock, reads the completion status, and returns the result.

#### rudp_conn_recv (0x180001590, 279 bytes)

Receives application data from the RUDP connection receive buffer. Corresponds to sb_transport_vtable_t.read_channel (vtable slot +0x20). Takes the connection object, destination buffer pointer, buffer capacity, output bytes-received pointer, and a timeout in milliseconds. Acquires the connection critical section and verifies ESTABLISHED state (state==5); returns 5023 if not connected. Returns error 170 (ERROR_BUSY) if a receive operation is already pending. Sets up the receive I/O descriptor at offsets +216..+236: stores the buffer pointer, total capacity, bytes received so far (zeroed), and MSS of 1460 bytes. Signals the receive event via SetEvent and calls rudp_fill_recv_buffer to copy any already-received in-order segments into the application buffer. Releases the lock, then waits on the receive event with the specified timeout via WaitForSingleObject. After the wait, re-acquires the lock, reads the completion status, and returns the result.

#### rudp_conn_abort (0x1800016A8, 103 bytes)

Abruptly terminates an RUDP connection by sending RST packets. Corresponds to sb_transport_vtable_t.close_channel (vtable slot +0x18) for abortive close. Acquires the connection critical section, then sends three RST packets via rudp_send_rst for redundancy to ensure the remote peer receives the reset even under packet loss. Releases the lock, then re-acquires it and calls rudp_signal_error with error code 10053 (WSAECONNABORTED) to notify any pending send/recv operations of the abortive disconnect. Unlike rudp_conn_close which performs graceful teardown with FIN, this function forces immediate connection reset. The triple-send pattern is used throughout the RUDP implementation for control packets to provide reliability without requiring acknowledgment.

#### rudp_conn_close (0x180001710, 280 bytes)

Performs graceful RUDP connection shutdown and full resource cleanup. Retrieves the transport manager and acquires its lock to decrement the reference count for this connection in the connection array, locating it by the connection port index minus the port base. Releases the transport manager lock, then acquires the connection lock, sets the state to CLOSED (state=7), calls rudp_signal_error with 10053 (WSAECONNABORTED) to wake any blocked send/recv operations, and releases the connection lock. Unregisters from the transport manager via transport_mgr_unregister_conn. If the socket (offset +464) is valid (not -1), calls shutdown(SD_BOTH=2). If the worker thread handle (offset +472) exists, signals it with INFINITE wait via WaitForSingleObject then closes the handle via CloseHandle. Finally closes the socket via closesocket and calls rudp_conn_cleanup to free all internal resources.

#### rudp_signal_error (0x180002860, 235 bytes)

Signals an error condition to any pending send and receive operations on the RUDP connection. Takes the connection pointer and a Winsock error code (e.g., 10053=WSAECONNABORTED, 10054=WSAECONNRESET). If the connection was in ESTABLISHED state (state==5), transitions it to CLOSE_WAIT (state=6). For the pending send operation (offset +160): if non-NULL, writes the error code to the I/O descriptor error field, zeros the bytes_transferred, and signals the send completion event via SetEvent. Clears the pending send pointer. Performs the identical wakeup for the pending recv operation (offset +200). This function is called during connection abort, close, RST/FIN reception, and keepalive timeout to notify the application layer of connection failure.

#### rudp_process_data (0x180002DC8, 332 bytes)

Processes an incoming DATA packet (type 2) by inserting the payload into the receive segment ring and sending an ACK. Only processes packets when in ESTABLISHED state (state==5). Extracts the data sequence number and the sender's latest ACK sequence via ntohs. Validates the data sequence falls within the receive window: it must be >= the recv ring's contiguous delivery point and <= the recv ring base plus the max window size (typically 128 segments). Updates the highest remote sequence watermark. Attempts to insert the data payload (packet bytes minus the 12-byte RUDP header) into the recv ring via rudp_seg_ring_insert. If insertion succeeds (segment was not a duplicate), records the current timestamp for the data receive timer, copies the payload data into the segment buffer, attempts to complete any pending application receive via rudp_fill_recv_buffer, and sends an ACK via rudp_send_ack. Returns 0.

---

### AIMD Congestion Control

#### rudp_process_ack (0x180002F14, 1172 bytes)

Processes an incoming ACK packet (type 3), performing cumulative acknowledgment, SACK bitmap processing, and AIMD congestion window adjustment. This is the most complex and largest function in the RUDP implementation. Only active in ESTABLISHED state (state==5). Extracts fields via ntohs: remote recv window, remote seq watermark, cumulative ACK sequence, and echo timestamp. Validates the cumulative ACK is within the send ring window. Updates the ACK receive timer. Computes the round-trip time (RTT) by looking up the echoed segment in the send ring and calculating current_time minus segment_send_time, storing in conn offset +456. Removes all cumulatively acknowledged segments from the send ring via rudp_seg_ring_remove loop. Decodes the SACK bitmap appended after the 16-byte ACK header via rudp_decode_sack_bitmap to selectively remove additional acknowledged segments. Calls rudp_fill_recv_buffer to deliver any newly-deliverable data. Implements the full AIMD algorithm: during slow start (cwnd < ssthresh), doubles cwnd each RTT; during congestion avoidance, applies additive increase `cwnd += (bytes_acked / cwnd) + aimd_increment * bytes_acked / 50.0`. Detects loss by computing `retransmit_count / total_sent` ratio -- if it exceeds 10%, triggers multiplicative decrease: `ssthresh = cwnd * 0.75`, `cwnd = ssthresh * 0.75`, with floor clamped to min_window (2) and ceiling to max_window (128).

#### rudp_process_eack (0x1800033A8, 398 bytes)

Processes an incoming EACK (Extended ACK / NACK response) packet (type 5), which is the peer's reply to a keepalive probe. Only active in ESTABLISHED state (state==5). Extracts the remote recv window, remote seq watermark, and cumulative ACK sequence via ntohs. Validates the cumulative ACK is within the send ring's valid range. Updates the EACK receive timer with the current performance counter timestamp. Tracks the highest remote recv window and remote seq watermark seen so far. Performs the same cumulative ACK removal loop as rudp_process_ack: iterates up to max_window times, removing all segments from the send ring with sequence <= ACK seq via rudp_seg_ring_remove. Decodes the SACK bitmap from the packet via rudp_decode_sack_bitmap. Calls rudp_fill_recv_buffer to deliver any newly-deliverable data. Updates the flight_size by recomputing it from the send ring count after removing acknowledged segments.

#### rudp_transmit_window (0x1800036E4, 937 bytes)

Core RUDP transmit window function that sends data segments from the send ring buffer, implementing congestion-controlled flow with AIMD pacing. Called from rudp_tick_timers on every 10ms tick when in ESTABLISHED state. First checks if there are any segments in the send ring; returns immediately if empty. Maintains a send credit accumulator (double at conn offset +384) that controls the rate of packet transmission. Each iteration computes elapsed time since the last send, and accumulates send credit based on two components: (1) a rate-limited credit proportional to the retransmission timeout (RTT-based pacing via offset +296/+456), and (2) a window-based credit proportional to cwnd (offset +360). The credit is consumed by sending packets: each packet deducts a minimum send credit from the accumulator. Iterates through segments starting from send ring base+1 up to the highest sequence. For each segment, performs window checks: the sequence must not exceed the remote advertised window, the flight size must be below cwnd, and pacing credit must be available. Sends each eligible segment via rudp_send_data and tracks retransmissions.

---

### SACK / Selective Acknowledgment

#### rudp_encode_sack_bitmap (0x180002180, 136 bytes)

Encodes a SACK (Selective Acknowledgment) bitmap from the segment ring buffer into a byte array. Takes the ring buffer pointer, output buffer, a pointer to the current write offset, the start sequence number, and end sequence number. Iterates from start+1 through end, checking each sequence number slot in the ring buffer for occupancy. For each group of up to 8 consecutive sequence numbers, builds a single byte where bit N is set if the segment at position (start + N) exists in the ring buffer, providing a compact bitmask of received out-of-order segments. After filling each byte (8 bits), increments the output offset and starts a new byte. If the last byte is partially filled, it is still included. This bitmap enables the receiver to inform the sender exactly which segments have been received, allowing selective retransmission of only the missing segments.

#### rudp_decode_sack_bitmap (0x180002208, 143 bytes)

Decodes a SACK bitmap received from the remote peer and removes acknowledged segments from the send ring buffer. Takes the send ring buffer pointer, the bitmap data pointer, and the bitmap byte count. Starting from the sequence number one past the cumulative ACK point (ring base sequence + 1), iterates through each byte of the bitmap. For each byte, tests all 8 bit positions: if bit J of byte I is set (tested via `(1 << j) & bitmap[i]`), the corresponding segment has been selectively acknowledged and is removed from the send ring via rudp_seg_ring_remove. The bitmap is packed LSB-first, so bit 0 of the first byte corresponds to the first sequence after the cumulative ACK. Returns 0.

---

### PRNG XOR Encryption

#### rudp_send_packet_encrypted (0x180003A90, 165 bytes)

Encrypts and sends an RUDP packet using the per-connection PRNG XOR cipher. Takes the connection pointer, source packet data, and packet size. Queries the current performance counter via QueryPerformanceCounter to obtain a 16-bit timestamp seed (low 16 bits). Reads the encryption buffer pointer from conn offset +152 (the send packet buffer). Initializes the PRNG state with the timestamp value and applies a streaming XOR cipher: for each byte, advances the PRNG state using the polynomial `state = 2006056960 * state - 1323075694 * HIWORD(state) - 2031501470`, then XORs the source byte with the low byte of the new state. After encryption, prepends the timestamp (in network byte order via htons) as the first 2 bytes of the encrypted packet, enabling the receiver to re-derive the same PRNG sequence for decryption. Finally calls the raw send function pointer at conn offset +48 (rudp_sendto_raw) to transmit the encrypted packet.

#### rudp_recv_loop (0x180004194, 302 bytes)

Main receive loop running on a dedicated thread for each RUDP connection. Continuously receives UDP datagrams and dispatches them to the RUDP protocol handler. Loops while the thread handle at conn offset +472 is non-NULL (used as a shutdown flag). Each iteration calls recvfrom on the connection's UDP socket (offset +464), reading into the receive buffer (offset +144) with max size 1024 bytes, and capturing the sender address into a local sockaddr_in structure. On socket error (-1), checks the error code via WSAGetLastError: errors 10060 (WSAETIMEDOUT), 10054 (WSAECONNRESET), and 10040 (WSAEMSGSIZE) are treated as non-fatal and the loop continues; any other error terminates the loop. On successful receive, decrypts the packet in-place using the per-connection PRNG XOR cipher: reads the 16-bit timestamp seed from the first 2 bytes of the packet via ntohs, initializes the PRNG with the same polynomial used by rudp_send_packet_encrypted, and XORs each byte to recover plaintext. Then acquires the connection lock and dispatches via rudp_dispatch_packet.

---

### Transport Vtable Functions

#### rudp_sendto_raw (0x1800042C4, 62 bytes)

Raw UDP sendto wrapper used as the default send callback at conn offset +48. Calls sendto on the connection's UDP socket (offset +464) to transmit a packet to the specified remote address. Parameters: connection pointer, data buffer, data length, destination sockaddr, and sockaddr length. Passes flags=0 to sendto. Checks the return value: if it equals the requested length, returns 0 (success). Otherwise calls WSAGetLastError and returns the Winsock error code. This is the lowest-level send function in the RUDP stack, sitting below the encryption layer and the protocol message constructors.

#### rudp_recvfrom_nop (0x180004304, 3 bytes)

No-op receive callback stub installed at conn offset +56 during connection creation. Simply returns 0 without performing any operation. This placeholder exists because the RUDP connection's receive path is handled by the dedicated rudp_recv_loop thread rather than through the callback interface used by the send path. The connection structure reserves function pointer slots for both send and receive callbacks (offsets +48 and +56), but only the send callback is actively used. The presence of this no-op ensures the function pointer is never NULL, preventing potential crashes if the receive callback slot is ever invoked.

#### rudp_tick_trampoline (0x18000432C, 5 bytes)

Thin trampoline function that forwards timer tick calls from the transport manager worker thread to rudp_tick_timers. Installed at conn offset +64 during connection creation. Takes the connection pointer and directly tail-calls rudp_tick_timers with the same argument. This indirection layer exists so that the function pointer at offset +64 can be a simple, non-virtual dispatch point that the worker thread calls without needing to know the specific timer implementation.

#### rudp_conn_destroy (0x180004308, 35 bytes)

Destructor for an RUDP connection object, installed at conn offset +72. Called when the reference count drops to zero in transport_mgr_unregister_conn or the worker thread cleanup path. First checks if the connection pointer is NULL (safety guard). If non-NULL, calls rudp_conn_cleanup to release all internal resources (events, ring buffers, I/O buffers, critical section), then frees the 480-byte connection structure itself via sb_free. Returns 0. This is the terminal cleanup function in the connection lifecycle, only invoked after all references have been released and the connection is fully disconnected.

#### rudp_conn_cleanup (0x1800024A4, 304 bytes)

Cleans up all dynamically allocated resources in an RUDP connection structure prior to deallocation. Closes the send completion event handle (offset +168) and recv completion event handle (offset +208) via CloseHandle. For the send ring buffer (offset +128): if non-NULL, iterates through all slots (up to capacity), freeing each occupied segment data buffer and segment descriptor via sb_free, then frees the slot array and the ring structure itself. Performs identical cleanup for the recv ring buffer (offset +136). Frees the send I/O buffer (offset +144) and recv I/O buffer (offset +152) if non-NULL. Finally calls DeleteCriticalSection on the connection CRITICAL_SECTION at offset +88. Does not free the connection structure itself -- that is handled by the caller (rudp_conn_destroy or the rudp_conn_create error path).

---

### Packet Construction (Send Functions)

#### rudp_send_syn (0x180003B38, 192 bytes)

Constructs and sends a SYN packet to initiate an RUDP connection handshake. Builds a 24-byte SYN packet: 2 bytes unused (filled by encryption layer), packet type 0 (SYN) at offset +2 via htons, local sequence number from conn offset +40 at offset +4, remote sequence number from conn offset +42 at offset +6, followed by the 16-byte PRNG encryption key from conn offset +260. The SYN carries the connection's encryption key material so the remote peer can derive the same PRNG state for packet decryption. Records the current performance counter timestamp in the SYN send timer at conn offset +316, used by rudp_tick_timers to determine when to retransmit the SYN if no SYNACK is received (100ms retry interval). Delegates the actual encryption and transmission to rudp_send_packet_encrypted with the 24-byte packet.

#### rudp_send_synack (0x180003BF8, 172 bytes)

Constructs and sends a SYNACK packet to complete the server side of the RUDP three-way handshake. Builds an 8-byte SYNACK packet: 2 bytes unused (filled by encryption layer), packet type 1 (SYNACK) at offset +2 via htons, local sequence number from conn offset +40 at offset +4, and remote sequence number from conn offset +42 at offset +6. Unlike the SYN packet, the SYNACK does not carry the PRNG key because the server already received and installed the key from the client SYN. Records the current performance counter timestamp in the SYNACK send timer at conn offset +320. Delegates to rudp_send_packet_encrypted for encryption and transmission. This function is called three times in succession during handshake completion to provide redundancy against packet loss.

#### rudp_send_data (0x180003CA4, 221 bytes)

Constructs and sends a DATA packet (type 2) carrying one segment's payload. Takes the connection pointer and a segment descriptor (the 40-byte structure from the segment ring). Accesses the segment data buffer pointer. Writes the packet header directly into the data buffer preceding the payload: packet type 2 (DATA) at +2 via htons, local sequence number at +4, remote sequence number at +6, the data sequence number from the segment at +8, and the sender's ACK sequence at +10. All multi-byte fields are converted to network byte order. Records the current performance counter timestamp in the data send timer at conn offset +324. Delegates to rudp_send_packet_encrypted with the total packet size being the data payload size plus the 12-byte RUDP DATA header.

#### rudp_send_ack (0x180003D84, 346 bytes)

Constructs and sends an ACK packet (type 3) acknowledging receipt of a specific data segment, including a SACK bitmap for out-of-order segments. Takes the connection pointer and the sequence number being acknowledged. Builds a variable-length ACK packet: packet type 3 at offset +2, local/remote sequence numbers at offsets +4/+6, the echo timestamp at offset +8 for RTT measurement, the highest remote sequence watermark at offset +10, the recv ring cumulative base sequence at offset +12, and the recv ring contiguous delivery sequence at offset +14. If the recv ring has gaps (contiguous != highest, meaning out-of-order segments exist), encodes a SACK bitmap via rudp_encode_sack_bitmap from the recv ring, appending the variable-length bitmap after the 16-byte fixed header. Records the current QPC timestamp in the ACK send timer at conn offset +328. Sends the packet via rudp_send_packet_encrypted with total size = 16 + SACK bitmap length.

#### rudp_send_keepalive (0x180003EE0, 197 bytes)

Constructs and sends a KEEPALIVE packet (type 4) to probe the remote peer and prevent the connection from timing out. Increments the global sequence counter at conn offset +304 (WORD, wrapping at 16 bits) to provide a unique probe identifier. Builds a 10-byte keepalive packet: packet type 4 at offset +2, local sequence number from conn offset +40 at offset +4, remote sequence number from conn offset +42 at offset +6, and the current probe sequence at offset +8. Records the current performance counter timestamp in the keepalive send timer at conn offset +332. Keepalive probes are sent by rudp_tick_timers when data is in flight but no ACK/DATA/EACK has been received within the keepalive interval. The remote peer responds with a NACK (type 5) upon receiving a keepalive.

#### rudp_send_nack (0x180003FA8, 329 bytes)

Constructs and sends a NACK (Negative Acknowledgment / Extended ACK) packet (type 5) in response to a received KEEPALIVE probe. Builds a variable-length NACK packet: packet type 5 at offset +2, local/remote sequence numbers at offsets +4/+6, the remote sequence watermark at offset +8, the recv ring cumulative base sequence at offset +10, and the recv ring contiguous delivery sequence at offset +12. If out-of-order segments exist in the recv ring (contiguous delivery point differs from the highest watermark), appends a SACK bitmap encoded via rudp_encode_sack_bitmap after the 14-byte fixed header. Records the current performance counter timestamp in the NACK send timer at conn offset +336. Delegates to rudp_send_packet_encrypted with total size = 14 + SACK bitmap bytes. The NACK response allows the keepalive sender to update its view of the receiver's state and selectively retransmit missing segments.

#### rudp_send_rst (0x1800040F4, 80 bytes)

Constructs and sends an RST (Reset) packet (type 6) to abruptly terminate the RUDP connection. Builds an 8-byte RST packet: packet type 6 at offset +2, local sequence number from conn offset +40 at offset +4, and remote sequence number from conn offset +42 at offset +6. Does not record any timer timestamp since RST is a terminal operation. Delegates to rudp_send_packet_encrypted. This function is called three times in succession by rudp_conn_abort to ensure delivery despite packet loss, since RST packets are not acknowledged by the protocol.

#### rudp_send_fin (0x180004144, 80 bytes)

Constructs and sends a FIN (Finish) packet (type 7) for graceful RUDP connection termination. Builds an 8-byte FIN packet: packet type 7 at offset +2, local sequence number at offset +4, remote sequence number at offset +6. Like RST, does not record a timer timestamp. FIN is sent three times by rudp_dispatch_packet when an RST is received (as an acknowledgment of the reset), ensuring the remote peer knows the connection is fully closed. Upon receipt, FIN causes the peer to transition to CLOSED state (state=7) and signal WSAECONNRESET (10054) to any pending I/O operations. The triple-send pattern provides reliability for this critical control message without requiring acknowledgment.

---

### Timer / Timeout Management

#### rudp_tick_timers (0x180003538, 427 bytes)

Timer tick handler called every 10ms by the transport manager worker thread for each active connection. Handles two state-dependent timer scenarios. In SYN_SENT state (state==4): Checks if more than 100ms have elapsed since the last SYN send (by comparing current QPC timestamp against offset +316). If so, retransmits a SYN packet via rudp_send_syn for connection retry. In ESTABLISHED state (state==5): First calls rudp_transmit_window to send pending data segments. Then checks keepalive timers: if data is in flight (send ring count is non-zero), checks the keepalive send timer against all four receive timers (data/ACK/keepalive/EACK receive timestamps). If the keepalive interval has elapsed without receiving any packets, sends up to three keepalive probes via rudp_send_keepalive. Additionally checks the retransmission timeout against the four receive timers; if ALL four timer thresholds are exceeded (no response to any packet type within the RTO), calls rudp_signal_error with WSAETIMEDOUT (10060) to declare the connection dead.

#### get_transport_manager (0x180001000, 116 bytes)

Singleton factory for the global RUDP transport manager object. On first call, allocates a 72-byte transport manager structure via sb_malloc and initializes it: sets up a CRITICAL_SECTION via InitializeCriticalSection at offset +0, zeroes the connection count (offset +48) and capacity (offset +52), queries the performance counter for a port base seed stored at offset +56, zeroes the connection pointer array (offset +40), grows the array to initial capacity of 1 slot via transport_mgr_grow_array, and zeroes the worker thread handle at offset +64. Subsequent calls return the cached g_transport_manager pointer without re-initialization. This is the central coordination point for all RUDP connections managed by this plugin.

#### transport_mgr_worker (0x180001B18, 275 bytes)

Transport manager worker thread main loop that drives the RUDP timer tick cycle for all active connections. Runs continuously while the thread handle at offset +64 of the transport manager is non-NULL (used as a shutdown signal). Each iteration acquires the transport manager lock, iterates through all connection slots (up to capacity), and for each non-NULL connection: increments its reference count, releases the manager lock, acquires the per-connection lock, calls the connection tick handler via the function pointer at offset +64 (rudp_tick_trampoline -> rudp_tick_timers), releases the per-connection lock, re-acquires the manager lock, decrements the reference count, and if it drops to zero, calls the destructor via the function pointer at offset +72 (rudp_conn_destroy), NULLs the slot, and decrements the active count. After processing all connections, releases the manager lock and sleeps for 10ms via Sleep(10). This 10ms tick interval drives all RUDP timing, retransmission, and keepalive logic.

#### transport_mgr_register_conn (0x180001C2C, 224 bytes)

Registers an RUDP connection with the transport manager by finding a free slot in the connection array. Acquires the transport manager lock, then scans the connection array for the first NULL slot, starting from index 0 up to the current capacity. The scan tracks both the array index and a port number (starting from the port base at offset +56). If no free slot is found, doubles the array capacity via transport_mgr_grow_array and retries. Once a free slot is found, stores the connection pointer in that slot, sets the connection port identifier (offset +40) to the port base plus the array index, sets the reference count to 1, and increments the active connection count. Releases the lock and returns 0 on success, or the error code from transport_mgr_grow_array on allocation failure.

#### transport_mgr_unregister_conn (0x180001D0C, 131 bytes)

Unregisters an RUDP connection from the transport manager and optionally destroys it if the reference count reaches zero. Acquires the transport manager lock, computes the array index from the connection port minus the port base, validates the index is within bounds and the slot contains the expected connection pointer with matching type tag. If validation fails, returns error 4312. Otherwise, decrements the close reference counter. If the counter reaches zero, calls the connection destructor via the function pointer at offset +72 (rudp_conn_destroy), NULLs the array slot, and decrements the active connection count. Releases the lock and returns 0 on success. This reference-counted unregistration ensures connections are not destroyed while the worker thread is still processing them.

#### transport_mgr_grow_array (0x180001D90, 138 bytes)

Grows the transport manager connection pointer array by the specified number of additional slots. Takes the transport manager pointer and the number of new slots to add. Computes the new total capacity and checks it does not exceed 0xFFFF (65535), returning error 8 (ERROR_NOT_ENOUGH_MEMORY) if exceeded. Allocates a new array of QWORD pointers via sb_malloc, copies existing entries from the old array using sb_memcpy, frees the old array via sb_free if non-NULL, updates the capacity field, and stores the new array pointer. Returns 0 on success or 8 on allocation failure. The 65535 connection limit corresponds to the 16-bit port identifier space used by the transport manager for connection indexing.

---

### Segment Ring Buffer Management

#### rudp_seg_ring_init (0x180001F34, 105 bytes)

Initializes an RUDP segment ring buffer structure (40 bytes). The ring buffer is a hash-table-like structure used for both send and receive segment tracking, keyed by sequence number modulo capacity. Takes the ring buffer pointer and capacity (typically 128 slots). Stores the capacity at offset +12, zeroes the count at offset +8, allocates a pointer array of capacity*8 bytes via sb_malloc and stores it at offset +0 (the slot array). Initializes all slots to NULL. Zeroes the cumulative acknowledged data counters at offsets +24 and +32 (QWORD accumulators for bytes acknowledged). Sets the base sequence number at offset +16 to 0 and the highest contiguous sequence at offset +20 to 0. Returns the ring buffer pointer. This structure is the core data structure for RUDP reliable delivery, maintaining out-of-order segments until they can be delivered in order.

#### rudp_seg_ring_insert (0x180001FA0, 299 bytes)

Inserts a new segment into the RUDP segment ring buffer at the position determined by sequence number. Takes the ring buffer pointer, sequence number (16-bit), total segment data size, and remaining data size. Performs three validation checks before insertion: (1) the sequence number must be greater than the highest contiguous delivered sequence, (2) it must not exceed the base sequence plus the ring capacity to prevent overflow, and (3) the slot at (seqnum % capacity) must be empty (no duplicate insertions). Allocates a 40-byte segment descriptor via sb_malloc containing: sequence number at offset +0 (WORD), retransmit count at offset +8 (DWORD, init 0), remaining data at offset +16 (DWORD), total data size at offset +20 (DWORD), data pointer at offset +24, and the data buffer pointer at offset +32 (allocated via sb_malloc). Stores the descriptor in the ring slot and increments the count. Returns 0 on success.

#### rudp_seg_ring_remove (0x1800020CC, 178 bytes)

Removes a segment from the RUDP segment ring buffer by sequence number. Takes the ring buffer pointer and the sequence number to remove (16-bit). Computes the slot index as (seqnum % capacity) and validates that the slot is occupied and contains the expected sequence number; returns error 4312 if not found or mismatched. On successful removal, accumulates the remaining data size from the segment descriptor into two QWORD counters at ring offsets +24 and +32, which track cumulative bytes acknowledged for AIMD congestion control statistics. Frees both the segment data buffer and the segment descriptor via sb_free, then NULLs the slot. Decrements the segment count. Advances the base sequence pointer forward past any empty slots until it reaches the contiguous delivery pointer, maintaining the invariant that base <= contiguous <= highest. Returns 0 on success.

---

### I/O Completion

#### rudp_complete_send (0x1800025D4, 125 bytes)

Attempts to complete a pending application-level send operation by copying data from the send ring buffer into the I/O descriptor. Called when new segments are acknowledged or when the send operation is first initiated. Checks if a send I/O operation is pending (offset +160 non-NULL). If so, calls rudp_copy_from_send_seg to transfer data from completed send ring segments into the application I/O buffer. If rudp_copy_from_send_seg returns WSAEWOULDBLOCK (10035), treats it as a non-fatal condition (no data available yet). If there is still remaining capacity in the I/O buffer (bytes_remaining > 0), returns without signaling completion, allowing more data to accumulate. On completion (buffer full or error), writes the final byte count into the bytes_transferred field, stores the error code, signals the send completion event via SetEvent, and clears the pending I/O pointer. Returns 0.

#### rudp_fill_recv_buffer (0x180002654, 339 bytes)

Fills a pending application-level receive buffer by extracting in-order data from the receive segment ring. Called when new data segments arrive or when a receive operation is initiated. Checks if a recv I/O operation is pending (offset +200 non-NULL). Iterates while the I/O buffer has remaining capacity. For each iteration, looks up the next in-order segment from the recv ring by sequence number. If the segment exists and has unread data (not already consumed and bytes_read < total), copies the available data via sb_memcpy from the segment data buffer into the application buffer, respecting both the segment remaining bytes and the application buffer remaining capacity. If no segment is ready and the ring is full, breaks to avoid deadlock. Otherwise, inserts a new empty segment placeholder for the next expected sequence to advance the delivery pointer. Returns 0 when the buffer is filled or no more data is available.

#### rudp_copy_from_send_seg (0x1800027A8, 181 bytes)

Copies data from the next completed send ring segment into the application I/O buffer. Looks up the segment at sequence (base_seq + 1) from the send ring buffer. Computes the slot index as (seqnum % capacity) and verifies the slot is occupied with the expected sequence number. If no segment is available at that position, returns WSAEWOULDBLOCK (10035) to indicate the send ring has no completed data ready. Otherwise, calculates the copyable byte count as the minimum of the segment remaining bytes and the I/O buffer remaining capacity. Copies the data via sb_memcpy from the segment data pointer to the I/O buffer. Advances both the segment read cursor and the I/O buffer transfer counter. If the segment is fully consumed, removes it from the ring via rudp_seg_ring_remove.

---

### Utility / Memory

#### sb_malloc (0x1800019B4, 54 bytes)

Heap memory allocator wrapper that lazily resolves HeapAlloc from ntdll/kernel32 via PEB walk. On first invocation, calls resolve_api_by_hash with hash 0x95CCC4F2 to locate HeapAlloc and caches the function pointer. Subsequent calls use the cached pointer directly. Invokes HeapAlloc with flags=0x40 (HEAP_ZERO_MEMORY) and the requested size. Returns the allocated pointer, or NULL on failure. This is the fundamental memory allocator used throughout the UDP plugin for all dynamic allocations including connection structures, ring buffers, packet buffers, and segment nodes.

#### sb_free (0x1800019EC, 53 bytes)

Heap memory deallocator wrapper that lazily resolves HeapFree via PEB walk. On first invocation, calls resolve_api_by_hash with hash 0xF3368A63 to locate HeapFree and caches the pointer. Includes a NULL-pointer guard: if the pointer is NULL, returns immediately without calling HeapFree. Otherwise, calls HeapFree to release the memory block. Used throughout the UDP plugin to free all dynamically allocated structures. Paired with sb_malloc for all memory lifecycle management in the plugin.

#### sb_memcpy (0x180001E1C, 120 bytes)

Memory copy wrapper that lazily resolves the CRT memcpy function. On first call, decrypts the string "memcpy" from an encrypted blob, converts it to wide string via sb_widen_string, and resolves the function address from msvcrt.dll via sb_resolve_crt_func. Caches the resolved pointer for subsequent calls. Parameters: destination pointer, source pointer, and byte count. Returns the destination pointer. Used throughout the RUDP implementation for copying packet data between segment ring buffers, I/O buffers, PRNG key material, and SACK bitmaps.

#### sb_decrypt_string (0x180004498, 185 bytes)

Decrypts an encrypted string blob using the ScatterBrain polynomial XOR cipher. Takes an output structure pointer (28 bytes) and a pointer to the encrypted blob. The blob format is: 2-byte little-endian key seed followed by XOR-encrypted ASCII data. Allocates a 4096-byte temporary buffer via sb_malloc. Initializes the PRNG state from the 16-bit key seed and applies streaming XOR decryption: for each byte, XORs the encrypted byte with the low byte of the current PRNG state, then advances the state using the polynomial `state = -42860544 * state - 135791246 * HIWORD(state) - 1043215206`. Decryption stops at the first null byte or after 4090 bytes. Zeroes the output structure fields and calls sb_utf8_to_wide to convert the decrypted UTF-8 string to a wide string stored in the output structure. Frees the temporary buffer. Returns the output structure pointer.

#### sb_string_free (0x180004554, 59 bytes)

Frees both the narrow (UTF-8/ANSI) and wide (UTF-16) string buffers within an sb_wstr_t-like string structure. The structure layout is: QWORD narrow_ptr at offset +0, DWORD narrow_len at offset +8, followed by QWORD wide_ptr at offset +16, DWORD wide_len at offset +24. If the narrow pointer is non-NULL, frees it via sb_free and zeroes the pointer and length. If the wide pointer is non-NULL, frees it via sb_free and zeroes the pointer and length. Called after every sb_decrypt_string operation to release the temporary string buffers once the decrypted string has been used.

#### sb_widen_string (0x180004590, 188 bytes)

Converts a narrow string to a wide (UTF-16) string, replacing the narrow buffer within the sb_wstr_t structure. Lazily resolves MultiByteToWideChar via resolve_api_by_hash (hash 0x98F67CEE) and caches the pointer. First calls MultiByteToWideChar with cbMultiByte=0 to query the required buffer size, using code page 0 (CP_ACP). Allocates the wide string buffer via sb_malloc. Calls MultiByteToWideChar again to perform the actual conversion. If the original narrow buffer is non-NULL, frees it and zeroes the pointer and length. Stores the new wide buffer and its character count. Returns the wide buffer pointer on success, or 0 on allocation failure.

#### sb_utf8_to_wide (0x18000464C, 233 bytes)

Converts a UTF-8 encoded byte string to a UTF-16 wide string, storing the result in the output structure. Lazily resolves MultiByteToWideChar via resolve_api_by_hash (hash 0xB8E3D378) and caches the pointer. Calls MultiByteToWideChar with code page 65001 (CP_UTF8), flags=0, the source UTF-8 string, length=-1 (null-terminated), and initially no output buffer to query the required size. Allocates a wide character buffer via sb_malloc. Calls MultiByteToWideChar again to perform the conversion. If the output structure already has a narrow string at offset +0, frees it. Similarly, if it already has a wide string at offset +16, frees it. Stores the new wide string pointer and character count. Returns 0 on success or 8 (ERROR_NOT_ENOUGH_MEMORY) on allocation failure.
