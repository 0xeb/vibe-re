# Blob 7 — DNS Tunnel Transport Plugin ("DNS")

## Summary

| Property | Value |
|----------|-------|
| File | Private archive artifact (available on vetted request) |
| Image Size | 0x9000 (36864 bytes) |
| Entry Point RVA | 0x14F0 |
| Functions | 51 (all renamed) |
| Sections | .text, .rdata, .data2, .data3, .idata |
| Timestamp | 0x58AEBA (2017-02-22/23) |
| idasql Port | 8207 |
| Version (CMD 102) | 203 |
| Plugin Name (CMD 103) | `"DNS"` (encrypted at `0x180005130`) |

## Role

**DNS tunnel transport — the most covert channel in the ScatterBrain suite.** Encodes C2 data inside DNS query subdomain labels, sends them as standard UDP:53 datagrams, and extracts C2 responses from DNS TXT records. Creates `socket(AF_INET, SOCK_DGRAM, 0)` with default port 53.

## Reclassification

Initially classified as "Raw TCP Transport" based on KERNEL32 + WS2_32 import profile. Deep analysis revealed DNS tunnel: the hex-encoded subdomain labels, DNS TXT record parsing, and port 53 default confirm this is a DNS-over-UDP covert channel.

## Imports (36 functions, 2 DLLs)

### KERNEL32.dll (23)
lstrcpyW, InitializeCriticalSection, DeleteCriticalSection, EnterCriticalSection, LeaveCriticalSection, QueryPerformanceCounter, QueryPerformanceFrequency, CreateThread, GetLastError, WaitForSingleObject, CloseHandle, Sleep, CreateEventW, GetSystemTime, GetCurrentThreadId, GetCurrentProcessId, GetTickCount, ResetEvent, SetEvent, GetProcAddress, LoadLibraryA, lstrcpyA, lstrlenA

### WS2_32.dll (13 by ordinal)
WSACleanup, WSAStartup, sendto, WSAGetLastError, socket, setsockopt, bind, getsockname, htons, shutdown, closesocket, ntohs, recvfrom

## Entry Point: DllEntryPoint (0x1800014F0)

| fdwReason | Command | Action |
|-----------|---------|--------|
| 0 | DETACH | No-op |
| 1 | ATTACH | Populates 6-slot vtable at `0x180006008` |
| 100 | START | WSAStartup(0x0101) + CreateThread(transport_tick_thread) |
| 101 | STOP | WaitForSingleObject, cleanup, WSACleanup |
| 102 | VERSION | Returns 203 |
| 103 | NAME | Decrypts plugin name string, copies via lstrcpyW |
| 104 | VTABLE | Returns `&unk_180006000` |

## Vtable (6 slots at `0x180006008`)

| Slot | Address | Name | Purpose |
|------|---------|------|---------|
| 0 | 0x180001074 | `cmd1_create_transport` | Allocate 480-byte conn, create UDP socket, enumerate local interfaces via GetAdaptersAddresses |
| 1 | 0x18000112C | `cmd2_connect_configure` | Two-phase: bind+SYN+recv thread, then copy DNS domain, set port (default 53), store DNS servers |
| 2 | 0x180001140 | `cmd3_send` | Queue send, segment data, MSS=1460, wait completion |
| 3 | 0x180001258 | `cmd4_recv` | Queue recv, reassemble, wait completion |
| 4 | 0x180001370 | `cmd5_flush_disconnect` | Send 3x FIN, signal WSAECONNABORTED |
| 5 | 0x1800013D8 | `cmd6_destroy_transport` | Graceful close: state=7, shutdown, thread join, closesocket |

## DNS Tunnel Protocol

### Outbound: DNS Query Encoding (`dns_encode_payload`, 0x18000393C, 664 bytes)

1. Each payload byte hex-encoded into 2 DNS-safe ASCII chars:
   - Low nibble: `value + 97` (maps to `'a'`-`'q'`)
   - High nibble: `value + 102` (maps to `'f'`-`'v'`)
2. Length indicator byte prepended: `count_of_non_dot_chars + 97`
3. Hex data fragmented into random 50-62 byte chunks (PRNG: `state = -764667742 - 1446266551 * state`)
4. Each chunk formatted as DNS label: `<length_byte><label_data>`
5. C2 domain name appended as final DNS labels
6. Result: `<len><hex_chunk1><len><hex_chunk2>...<len>example<len>com<0>`

### Inbound: DNS TXT Record Decoding (`dns_decode_response`, 0x180003BD4, 394 bytes)

1. Skip DNS query section
2. Validate answer: compression pointer `0xC00C`, type `0x0010` (TXT), class `0x0001` (IN)
3. Extract TXT record payload
4. Reverse hex encoding
5. XOR-decrypt with rolling PRNG cipher (same as blob_6)
6. Dispatch by type: 0=SYN-ACK, 1=DATA, 3=FIN

### Packet Encryption (same cipher as blob_6)
```
seed = (uint16_t)QueryPerformanceCounter()
key = htons(seed)
for each byte:
    key = 2006056960 * key - 1323075694 * HIWORD(key) - 2031501470
    encrypted = plaintext ^ (key & 0xFF)
```

## Connection State Machine

| State | Name | Description |
|-------|------|-------------|
| 1 | INIT | Socket created, interfaces enumerated |
| 2 | SYN_SENT | SYN sent, recv thread started |
| 4 | RESOLVING | DNS domain configured, 3x keepalives sent, polling for SYN-ACK |
| 5 | ESTABLISHED | Data transfer active |
| 6 | CLOSING | FIN received or error |
| 7 | CLOSED | Terminal |

### Connect Sequence (`cmd2_connect_configure_impl`, 0x180002A4C)

**Phase 1** (state 1 -> 2):
- Build SYN packet with `htons(2)` type
- `bind(socket, INADDR_ANY:0)` + `getsockname` for local port
- `CreateThread(udp_recv_thread)` to start recv loop
- Transition to state 2

**Phase 2** (state 2 -> 4 -> 5):
- `lstrcpyA(conn+0x17C, config+8)` copies C2 DNS domain
- Read port from config; if zero, defaults to **53**
- Copy up to 4 target DNS server IPs
- Send 3x keepalive packets
- Poll 100 iterations x 100ms = 10s timeout for ESTABLISHED

## Network Interface Enumeration

`udp_init_and_enumerate_addrs` (0x180002800): Dynamically resolves `GetAdaptersAddresses` from `iphlpapi.dll`. Enumerates all IPv4 adapters with flags `GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_DNS_SERVER` (0x90). Stores up to 16 unicast IP addresses. Enables DNS queries from multiple local interfaces for diversity/redundancy.

## Thread Model

1. **Transport Tick Thread** (`transport_tick_thread`, 0x1800017E0): Single global, 10ms `Sleep` loop, calls each connection's tick function for retransmission/keepalive
2. **Per-Connection Recv Thread** (`udp_recv_thread`, 0x1800025A8): Blocking `recvfrom` loop, decrypt + parse DNS responses + dispatch
3. **Caller threads**: Block on events for send/recv completion

## Comparison with blob_6 (RUDP)

| Aspect | blob_6 (RUDP, v202) | blob_7 (DNS, v203) |
|--------|---------------------|---------------------|
| Transport | Raw UDP datagrams | DNS queries / TXT records |
| Data encoding | Raw binary | Hex-encoded subdomain labels (2x expansion) |
| Default port | Configurable | 53 (DNS standard) |
| Domain name | Not used | Core config parameter |
| Congestion control | Full AIMD | Simpler backoff |
| Stealth | Low (custom UDP) | **High** (blends with DNS traffic) |
| Bandwidth | Higher | Lower (2x expansion + DNS overhead) |
| Extra DLL | None | `iphlpapi.dll` for adapter enum |
| Functions | 54 | 51 (simpler) |

**Design rationale**: blob_6 offers higher throughput for bulk transfers, while blob_7 offers maximum stealth since DNS:53 traffic is almost universally permitted and rarely inspected.

## Encrypted Strings (6 total)

| Address | Decrypted | Used For |
|---------|-----------|----------|
| 0x180005130 | (plugin name) | CMD 103 response |
| 0x180005138 | (DLL name) | CRT functions |
| 0x180005148 | (function name) | memcpy resolution |
| 0x180005158 | (DLL name) | memset resolution |
| 0x180005168 | `iphlpapi.dll` | Adapter enumeration DLL |
| 0x180005180 | `GetAdaptersAddresses` | Adapter enumeration API |

## PEB-Resolved APIs (6)

| Hash | API |
|------|-----|
| 0x95D9FE52 | LocalAlloc |
| 0xF339F5E3 | LocalFree |
| 0xBDA26FE6 | LoadLibraryA |
| 0xA16DC157 | GetProcAddress |
| 0xB8D629F8 | MultiByteToWideChar |
| 0x991AB7EE | WideCharToMultiByte |

## All 51 Functions

All renamed — zero `sub_*` remaining. Key functions by category:

- **Entry**: `DllEntryPoint`
- **Vtable**: `cmd1_create_transport`, `cmd2_connect_configure`, `cmd3_send`, `cmd4_recv`, `cmd5_flush_disconnect`, `cmd6_destroy_transport`
- **DNS Protocol**: `dns_encode_payload`, `dns_decode_response`, `build_and_send_udp_packet`, `process_incoming_dns_packet`, `handle_syn_ack`, `handle_data_packet`, `build_ack_response`, `send_keepalive`, `send_fin_packet`
- **Network**: `udp_init_and_enumerate_addrs`, `udp_recv_thread`, `udp_sendto_wrapper`, `udp_retransmit_or_advance`, `udp_poll_tick`
- **Ring Buffer**: `seq_ring_init`, `seq_ring_alloc_slot`, `seq_ring_free_slot`
- **Connection**: `transport_state_init`, `transport_cleanup`, `transport_config_init`, `transport_error_complete`
- **Infrastructure**: `transport_mgr_get_or_create`, `transport_mgr_register`, `transport_mgr_unregister`, `transport_tick_thread`
- **Utility**: `local_alloc`, `local_free`, `resolve_export_by_hash`, `resolve_dll_export`, `memcpy_wrapper`, `decrypt_string`

## Detailed Function Reference

### API Resolution

#### resolve_export_by_hash (0x1800016EC, 241 bytes)

Walks the PEB InLoadOrderModuleList to locate kernel32.dll by hashing each module base name with a ROR8+XOR algorithm (right-rotate 8 bits, XOR with constant 0x7C35D9A3, case-folded via OR 0x20). Matches when the hash equals 0xFD5D1D81 (kernel32.dll). Then walks the module PE export directory: for each exported function name, applies the same ROR8+XOR hash (without case folding) and compares against the caller-supplied hash. Resolves the matching function RVA through the ordinal table and returns the absolute address. Returns NULL if no module or export matches. This is the primary API resolution mechanism used by the ScatterBrain framework to avoid static imports.

#### resolve_dll_export (0x180001B5C, 159 bytes)

Resolves a named export from msvcrt.dll by function name string. On first call, decrypts the string "msvcrt.dll" via decrypt_string, lazy-resolves kernel32!LoadLibraryA via API hash 0xBDAD94E6, loads the library, and caches the module handle in g_pfnmsvcrt_dll_2. Also lazy-resolves kernel32!GetProcAddress via hash 0xA16B3F57. Then calls GetProcAddress with the msvcrt handle and the caller-provided function name. Returns the resolved function pointer. This is the mechanism used to resolve CRT functions like memcpy and memset that are not in the kernel32 export table.

### Plugin Protocol / Dispatch

#### DllEntryPoint (0x1800014F0, 396 bytes)

Plugin DLL entry point dispatching on fdwReason using a switch-chain. Reason 1 (DLL_PROCESS_ATTACH): populates the 6-entry sb_transport_vtable_t at g_transport_vtable with function pointers for cmd1 through cmd6 (create, connect, send, recv, flush, destroy). Reason 100: initializes Winsock via WSAStartup(MAKEWORD(1,1)), creates the transport manager singleton, spawns the transport_tick_thread via CreateThread, and stores the thread handle at manager offset +64. Reason 101: tears down the manager -- signals the tick thread to exit, waits on it, closes its handle, frees the slot array and manager struct, then calls WSACleanup. Reason 102: writes the plugin version number 203 (0xCB) to *lpReserved. Reason 103: decrypts the plugin name string via decrypt_string and copies it to the caller buffer via g_pfnUnk_5000 (wcscpy). Reason 104: stores a pointer to g_transport_vtable into *lpReserved. Always returns TRUE.

#### transport_mgr_get_or_create (0x180001000, 116 bytes)

Lazily initializes and returns the global transport manager singleton (g_transport_mgr). On first call, allocates a 72-byte structure via local_alloc, initializes its embedded critical section (offset +0), zeroes the active-count (offset +48) and capacity (offset +52) fields, queries the system timer resolution into offset +56, and calls transport_mgr_grow_slots to allocate the initial slot pointer array with 1 entry. The thread handle at offset +64 is initialized to NULL. Subsequent calls simply return the cached pointer. Returns the pointer to the manager struct on success, or NULL if allocation fails.

#### transport_mgr_register (0x1800018F4, 224 bytes)

Registers a transport instance in the manager slot array. Acquires the manager lock, scans the slot pointer array (offset +40) for the first NULL entry, starting from the base slot ID (offset +56). If no empty slot is found, releases the lock and calls transport_mgr_grow_slots to double the array capacity, then retries. Once a free slot is found, stores the transport pointer, computes and stores the absolute slot ID (base + index) at transport offset +40, sets the initial refcount to 1 at transport offset +36, and increments the active count at manager offset +48. Releases the lock and returns 0 on success, or the error from grow_slots if allocation fails.

#### transport_mgr_unregister (0x1800019D4, 131 bytes)

Unregisters a transport from the manager by its slot ID. Acquires the manager lock, computes the array index from the transport slot ID (offset +40) minus the base (manager offset +56), validates that the index is within bounds and the stored pointer matches the transport. Decrements the refcount at transport offset +36. If the refcount reaches zero, calls the destroy callback at transport offset +72 (udp_destroy for DNS), NULLs the slot, and decrements the active count at manager offset +48. Returns 0 on success or 4312 if the slot ID is invalid or the transport pointer does not match. Releases the manager lock before returning.

#### transport_mgr_grow_slots (0x180001A58, 138 bytes)

Grows the transport manager slot pointer array by the specified number of entries. Validates that the total (current capacity + param1) does not exceed 0xFFFF (65535), returning error 8 (ERROR_NOT_ENOUGH_MEMORY) if so. Allocates a new buffer via local_alloc with size = total * 8, copies existing slot pointers via memcpy_wrapper, frees the old array, updates the capacity at manager offset +52, and stores the new buffer at offset +40. Returns 0 on success or 8 on allocation failure. The zero-init from local_alloc ensures new slots start as NULL.

#### transport_tick_thread (0x1800017E0, 275 bytes)

Background thread that drives all transport polling. Runs in a continuous loop while the thread handle at manager offset +64 is non-NULL. Each iteration acquires the manager lock, iterates all registered transport slots (offset +40 array, capacity at +52), increments each transport refcount at offset +36, releases the manager lock, acquires the per-transport lock at offset +88, and calls the transport poll_tick callback at offset +64 (udp_poll_tick for DNS transports). After the callback, releases the transport lock, re-acquires the manager lock, and decrements the refcount. If the refcount reaches zero, calls the destroy callback at offset +72 and NULLs the slot. Sleeps 10ms between iterations via g_pfnUnk_5050 (Sleep). Returns 0 when exiting.

### DNS Query Construction

#### build_and_send_udp_packet (0x180003474, 572 bytes)

Constructs and transmits a DNS query packet encapsulating tunnel data. First XOR-encrypts the payload using the PRNG cipher: generates a random 16-bit transaction ID from QueryPerformanceCounter, seeds the PRNG (multiplier 0x77900000, subtract 0x4EDD91AE and 0x7911AAFE), and XORs each payload byte. Prepends the transaction ID in network byte order. Builds a standard 12-byte DNS header: auto-incrementing query ID (offset +304), flags=0x0100 (standard query, recursion desired), QDCOUNT=1, ANCOUNT=NSCOUNT=ARCOUNT=0. Calls dns_encode_payload to hex-encode the encrypted payload as DNS subdomain labels, appends the C2 domain suffix, and adds QTYPE=A (1) / QCLASS=IN (1) as a 4-byte trailer. Assembles everything into a dynbuf. If a specific server IP is known (offset +376 != 0), sends to that address on the configured port (offset +444). Otherwise, iterates all discovered DNS server addresses (offset +312, count at +308) and sends the query to each one, maximizing the chance of reaching the C2 resolver. Frees temporary buffers.

#### send_keepalive (0x1800036B0, 192 bytes)

Sends a SYN/keepalive packet to initiate or maintain the DNS tunnel connection. Constructs an 8-byte protocol header: packet type 0 (SYN) at offset +0, local session ID from transport +40 at offset +4, remote session ID from transport +42 at offset +6 -- all converted to network byte order via htons (g_pfnUnk_5100). Appends the 16-byte XOR key from transport offset +260 via memcpy_wrapper, forming a 24-byte payload. Timestamps the send at offset +448 using QueryPerformanceCounter / tick frequency for RTT tracking. Calls build_and_send_udp_packet to encrypt, DNS-encode, and transmit the packet. Used both during initial handshake (3 rapid SYNs) and by udp_poll_tick for periodic keepalive in SYN_SENT state.

#### send_fin_packet (0x1800038EC, 80 bytes)

Sends a FIN (connection teardown) packet over the DNS tunnel. Constructs an 8-byte header with packet type 3 (FIN) at offset +0, local session ID from transport +40 at offset +4, and remote session ID from transport +42 at offset +6, all in network byte order via htons. Passes the 8-byte payload to build_and_send_udp_packet for PRNG XOR encryption, DNS hex-encoding, and transmission. Called three times in rapid succession by cmd5_flush_disconnect to ensure the server receives the disconnect signal despite potential UDP packet loss. Returns the result from build_and_send_udp_packet.

#### build_ack_response (0x180003770, 379 bytes)

Constructs and sends a DATA/ACK packet in the reliable DNS tunnel protocol. Builds an 18-byte header: packet type 1 (DATA) at offset +0, local session ID (+2), remote session ID (+4), send sequence number from the ring slot ptr_arg1[0] (+8), recv ACK sequence from the send ring high-water mark at +18 (+10), recv window edge from the send ring low-water at +16 (+12) -- all in network byte order. Constructs a 4-byte SACK bitmap starting from the send ring high-water + 1: for each of 32 positions, sets a bit if the corresponding ring slot is occupied, using byte-level packing (8 bits per byte, 4 bytes total). Appends any outbound payload from the ring slot data buffer (slot +24, length slot +12). Calls build_and_send_udp_packet with the total (18 + payload_size) to encrypt and transmit. Returns the result from build_and_send_udp_packet.

### Subdomain Hex Encoding

#### dns_encode_payload (0x18000393C, 664 bytes)

Encodes a binary payload into DNS query name format for the DNS tunneling exfiltration channel. Uses a two-character-per-byte nibble encoding where the low nibble maps to characters a through p (value + 97) and the high nibble maps to characters f through u (value + 102), producing a case-insensitive hex-like representation. Prepends a single-byte length indicator: the domain suffix non-dot character count encoded as (count + 97), allowing the server to distinguish payload from domain. Splits the encoded data into DNS labels of random length between 50 and 62 bytes (using the PRNG: (g_prng_state + QPC) mod 13 + 50), each prefixed by its length byte per RFC 1035 label format. After all payload labels, appends the C2 domain suffix (ptr_arg3, e.g. example.com) by parsing it into dot-separated labels with length prefixes and a zero terminator. Writes the complete DNS name into the caller dynbuf via dynbuf_append. Frees all intermediate buffers.

### TXT Record Parsing

#### dns_decode_response (0x180003BD4, 394 bytes)

Decodes a DNS TXT record response to extract the tunneled binary payload. Parses DNS label-length prefixed segments: reads a length byte, copies that many bytes into a dynbuf, advances the cursor, and repeats until a zero-length label (name terminator) is encountered. Updates the caller offset pointer (ptr_arg3) to track position within the DNS packet. From the concatenated label data, extracts the first byte as a length indicator (decoded as (byte OR 0x20) - 97, yielding the non-dot character count of the domain suffix). The remaining bytes are the hex-encoded payload. Reverses the nibble encoding from dns_encode_payload: for each pair of characters, the first byte minus 97 gives the low nibble and the second byte minus 102 gives the high nibble, combined as (high shifted left 4) OR low. Writes the decoded binary data into the caller dynbuf. Returns 0 on success or 13 (ERROR_INVALID_DATA) on parse failure (invalid nibble values, truncated data, or empty response).

#### process_incoming_dns_packet (0x180002EE4, 566 bytes)

Main dispatcher for incoming DNS tunnel responses received by udp_recv_thread. Validates the DNS header response flags (checking the RCODE field in the flags word at offset +2 is 0, meaning no error). Calls dns_decode_response on the question section (starting at byte 12) to skip the query name. Validates the answer section structure: checks for QTYPE=TXT (16), QCLASS=IN (1), compression pointer 0xC00C, and RRTYPE=TXT/RRCLASS=IN in the answer record. Calls dns_decode_response again on the TXT RDATA to extract the payload. Decrypts the payload using the PRNG XOR cipher seeded from the first two bytes (transaction ID) -- the same IMUL-based PRNG used for encryption in build_and_send_udp_packet (multiplier 0x77900000, subtractors 0x4EDD91AE and 0x7911AAFE). Dispatches by packet type at payload offset +2: type 0 calls handle_syn_ack, type 1 calls handle_data_packet, type 3 handles FIN (validates session IDs, transitions to CLOSED=7, calls transport_error_complete with 10054). Frees all temporary buffers.

#### handle_syn_ack (0x18000311C, 235 bytes)

Processes a SYN-ACK response during the DNS tunnel handshake. Only active when the transport is in SYN_SENT state (4) at offset +256. Extracts the local session ID from payload offset +6 and the remote session ID from payload offset +4, both converted from network byte order via ntohs (g_pfnUnk_5118). Validates that the returned local session ID matches the one stored at transport offset +40; returns -1 on mismatch. On match, transitions to ESTABLISHED (5), stores the remote peer session ID at offset +42, copies the server sockaddr IP (param2+4) into the C2 server address at transport offset +376 (used for subsequent directed sends), and timestamps the connection establishment using QueryPerformanceCounter / tick frequency. Stores the timestamp at offset +460 for idle timeout tracking. Returns 0.

#### handle_data_packet (0x180003208, 619 bytes)

Processes an incoming DATA packet (type 1) in the reliable DNS tunnel protocol. Only active in ESTABLISHED state (5). Extracts five fields from the packet header (all network byte order): local session ID (offset +6), remote session ID (+4), recv sequence number (+8), send ACK number (+10), and send window edge (+12). Validates session IDs match transport +40/+42 and all sequence numbers fall within their respective windows. Updates the transport high-water marks for remote send/recv tracking at offsets +80 and +82. Timestamps the activity at +460. Processes cumulative ACK: frees all send ring slots from low_water+1 up to the ACK number. Processes selective ACK: reads the 4-byte SACK bitmap at payload offset +14, iterating 32 bits to selectively free acknowledged send ring slots beyond the cumulative ACK. Calls recv_fill_segments to push reassembled data to the user. If there is payload beyond the 18-byte header, allocates a recv ring slot for the sequence and copies the payload via memcpy_wrapper.

### DNS Wire Format

This category is covered by the functions listed under **DNS Query Construction** and **TXT Record Parsing** above. The wire-level DNS packet assembly occurs in `build_and_send_udp_packet` (12-byte DNS header construction, QTYPE/QCLASS trailer) while `process_incoming_dns_packet` handles wire-level DNS answer validation (compression pointers, RRTYPE, RRCLASS, RCODE checks).

### Transport Vtable Functions

#### cmd1_create_transport (0x180001074, 181 bytes)

Vtable slot 0 (sb_transport_vtable_t offset +0x00): creates a new DNS transport instance. Allocates a 480-byte transport state struct via local_alloc, calls transport_state_init to initialize critical sections, events, sequence rings, PRNG state, and the 16-byte XOR key. Sets the transport type ID to 7 (DNS) at offset +0, then installs four callback function pointers: udp_sendto_wrapper at +48, udp_sendto_noop at +56, udp_poll_tick at +64, and udp_destroy at +72. Calls udp_init_and_enumerate_addrs to create a UDP/DGRAM socket, set socket buffer sizes and timeouts, and enumerate local IPv4 addresses via GetAdaptersAddresses. On failure, calls transport_cleanup and local_free to tear down the partially-initialized instance. Returns 0 on success with the transport pointer stored in *this_ptr, or a Winsock error code on failure.

#### cmd2_connect_configure (0x18000112C, 18 bytes)

Vtable slot 1 (sb_transport_vtable_t offset +0x08): validates the connect/configure request before delegating to cmd2_connect_configure_impl. Checks the protocol subtype field at param1+6; if nonzero, rejects the request immediately with error 10042 (WSAENOPROTOOPT), ensuring this transport only handles the base DNS tunneling protocol. Otherwise passes all parameters through to the implementation function. Takes the transport pointer as this_ptr and the connect parameter block as param1. Returns 0 on success or a Winsock error code on failure.

#### cmd2_connect_configure_impl (0x180002A4C, 507 bytes)

Two-phase connect implementation for the DNS transport. Phase 1 (state CONFIGURED=1): binds the UDP socket to a random ephemeral port by calling bind with AF_INET/port=0, retrieves the bound address via getsockname, spawns the udp_recv_thread via CreateThread, and transitions to BOUND (2). Phase 2 (state BOUND=2): acquires the transport lock, copies the C2 domain string from param1+8 into the domain buffer at offset +380 via g_pfnUnk_50A8 (wcscpy), reads the port from param1+0 (defaults to 53 if zero), stores it at offset +444, and transitions to SYN_SENT (4). Copies up to 4 additional DNS server IPs from param1+4104..+4116 into the address array at +312. Sends three initial SYN keepalive packets via send_keepalive. Then polls in a busy loop (100 iterations, 100ms sleep each = 10s total) waiting for state to transition to ESTABLISHED (5) via a SYN-ACK response. Returns 0 if connected, or 10060 (WSAETIMEDOUT) if the handshake times out.

#### cmd3_send (0x180001140, 279 bytes)

Vtable slot 2 (sb_transport_vtable_t offset +0x10): sends data over the DNS tunnel. Acquires the transport critical section at offset +88, verifies the connection state is ESTABLISHED (5) at offset +256 -- returning 5023 (WSAENOTCONN) if not -- and checks that no send operation is already pending at offset +160 (returns 170 / ERROR_BUSY if so). Populates the send IO request descriptor at offsets +176..+196 with the caller buffer pointer, total size, bytes-transferred counter (initially 0), and a 1460-byte segment limit (matching the DNS tunnel MTU). Signals the send completion event and calls send_complete_check to begin draining data into the send ring buffer. Releases the lock, waits on the completion event with the caller-supplied timeout (param4), then re-acquires the lock to read the final status code from offset +196 and bytes transferred from +188 into *dw_arg3. Clears the pending request pointer before returning. Returns 0 on success or a Winsock error code on timeout/failure.

#### cmd4_recv (0x180001258, 279 bytes)

Vtable slot 3 (sb_transport_vtable_t offset +0x18): receives data from the DNS tunnel. Mirrors the structure of cmd3_send but uses the recv IO request at offsets +200..+236. Acquires the transport critical section, verifies ESTABLISHED state (returns 5023 if not), checks no recv is pending (returns 170 if so), then fills the recv descriptor with the caller buffer pointer, size, zero-initialized bytes-transferred, and 1460-byte segment limit. Signals the recv event and calls recv_fill_segments to copy reassembled data from the recv sequence ring into the user buffer. Releases the lock, waits on the completion event with timeout param4, re-acquires the lock, reads bytes transferred into *dw_arg3 and status from offset +236. Clears the pending request pointer. Returns 0 on success or a Winsock error code.

#### cmd5_flush_disconnect (0x180001370, 103 bytes)

Vtable slot 4 (sb_transport_vtable_t offset +0x20): performs a graceful disconnect of the DNS tunnel. Acquires the transport critical section, then sends three FIN packets in rapid succession via send_fin_packet (type 3 in the DNS tunnel protocol) to maximize the chance the server receives the disconnect signal despite UDP unreliability. Releases the lock, re-acquires it, then calls transport_error_complete with error 10053 (WSAECONNABORTED) to signal completion on any pending send or recv operations, transitioning the state from ESTABLISHED (5) to CLOSING (6). Returns 0 unconditionally.

#### cmd6_destroy_transport (0x1800013D8, 280 bytes)

Vtable slot 5 (sb_transport_vtable_t offset +0x28): fully destroys a DNS transport instance. Reads the transport slot ID from offset +40 and type from offset +0, increments the refcount in the transport manager to prevent premature cleanup during teardown. Transitions state to CLOSED (7) at offset +256, calls transport_error_complete with 10053 (WSAECONNABORTED) to abort any pending IO. Unregisters from the manager, shuts down the UDP socket by calling g_pfnUnk_5108 (closesocket) with SD_BOTH, then signals the recv thread exit event and waits for it with WaitForSingleObject(INFINITE). Closes the thread handle, closes the socket (setting it to INVALID_SOCKET at offset +464), and performs a second unregister to drop the refcount. Returns 0.

### Reliable Transport / Retransmission

#### udp_poll_tick (0x1800026C4, 277 bytes)

Poll tick callback invoked by the transport_tick_thread every 10ms for each registered DNS transport. Handles two states: In SYN_SENT state (4), lazy-initializes the global tick frequency from QueryPerformanceFrequency (dividing by 1000 for ms resolution), then sends periodic keepalive/SYN packets every 1000ms via send_keepalive to establish the connection. In ESTABLISHED state (5), computes elapsed time since last activity; if within the retransmit timeout (offset +288), calls udp_retransmit_or_advance to handle retransmissions and window advancement. If the idle timeout is exceeded, transitions to CLOSED (7) and calls transport_error_complete with WSAECONNRESET (10054) to abort the session. Returns 0.

#### udp_retransmit_or_advance (0x180002C48, 668 bytes)

Manages retransmission and send window advancement for the reliable DNS tunnel. Scans the recv ring buffer (offset +128) from the low-water mark to the high-water mark looking for segments that need retransmission. Prioritizes untransmitted segments (retransmit count at slot +8 == 0) and among already-transmitted segments, selects the one with the oldest timestamp (slot +4). If a segment is found, timestamps it, increments its retransmit counter, resets the adaptive backoff counter at offset +456, and calls build_ack_response to re-send it as a DATA+ACK packet. If no segments need retransmission, uses adaptive backoff: increments the backoff delay by 10ms per tick (capped at 3000ms at offset +456). When the backoff timer expires, constructs an empty ACK probe with the next expected sequence number and sends it via build_ack_response to keep the connection alive and acknowledge received data.

#### udp_recv_thread (0x1800025A8, 213 bytes)

Dedicated receive thread for the DNS transport. Runs a continuous loop while the thread event pointer at transport offset +472 (this_ptr[59]) is non-NULL. Each iteration calls recvfrom (g_pfnDNS) on the UDP socket (offset +464) into the 1024-byte recv scratch buffer (offset +144), with a 16-byte sockaddr_in output. On SOCKET_ERROR (-1), checks the WSA error via g_pfnUnk_50D8 (WSAGetLastError): tolerates WSAETIMEDOUT (10060), WSAECONNRESET (10054), and WSAEMSGSIZE (10040) by continuing the loop; all other errors cause the thread to exit. On successful receipt of 8 or more bytes (minimum DNS tunnel packet size), acquires the transport lock at offset +88 and calls process_incoming_dns_packet to parse and dispatch the response. Releases the lock after processing. Returns 0 on exit.

#### udp_sendto_wrapper (0x180002680, 62 bytes)

Thin wrapper around the Winsock sendto function. Calls g_pfnUnk_50D0 (sendto) on the UDP socket stored at transport offset +464, passing the buffer, size, zero flags, and the destination sockaddr with its length. Compares the return value against the expected byte count; returns 0 if they match (full send succeeded) or calls WSAGetLastError (g_pfnUnk_50D8) and returns the Winsock error code on failure. Installed as the primary send callback at transport offset +48.

#### udp_sendto_noop (0x1800026C0, 3 bytes)

No-op stub that always returns 0. Installed as the alternate send callback at transport offset +56 during transport creation. This callback is used when the transport does not yet have a valid socket or destination address configured, effectively silencing any send attempts before the connection is established. Takes no meaningful parameters.

#### udp_init_and_enumerate_addrs (0x180002800, 586 bytes)

Initializes the UDP networking layer for the DNS transport. Allocates two 1024-byte scratch buffers at offsets +144 (recv) and +152 (send). Calls transport_config_init to register with the manager, set default window sizes, and allocate sequence rings. Creates a UDP socket via g_pfnUnk_50E0 (socket, AF_INET=2, SOCK_DGRAM=2), sets send/recv buffer sizes to 128KB via setsockopt (SO_SNDBUF=4097, SO_RCVBUF=4098), and configures 1000ms send/recv timeouts (SO_SNDTIMEO=4101, SO_RCVTIMEO=4102). Then enumerates local network adapters by lazy-resolving GetAdaptersAddresses from iphlpapi.dll (via encrypted string decryption and LoadLibrary/GetProcAddress). Calls GetAdaptersAddresses with AF_INET in a retry loop that doubles the buffer on ERROR_BUFFER_OVERFLOW (111). Walks the adapter linked list, collecting up to 16 unicast IPv4 addresses into the address array at transport offset +312 (counter at +308). Returns 0 on success or 8 on allocation failure.

#### udp_destroy (0x1800027DC, 35 bytes)

Destroy callback for DNS transport instances, installed at transport offset +72. Called when the transport refcount drops to zero in the manager. If the transport pointer is non-NULL, calls transport_cleanup to release all ring buffers, event handles, scratch buffers, and the critical section, then frees the 480-byte transport struct itself via local_free. Returns 0. This is the final destructor in the transport lifecycle.

### Connection State Management

#### transport_state_init (0x180001E48, 524 bytes)

Initializes the 480-byte transport state structure for a DNS tunnel connection. Zeros the type ID at +0, callback pointers at +48..+72, and the slot/refcount at +36..+44. Creates the embedded critical section at offset +88 via g_pfnUnk_5008 (InitializeCriticalSection). Allocates send and recv completion events at offsets +168 and +208 using g_pfnUnk_5058 (CreateEvent, manual-reset). Zeroes the send IO request (offsets +160..+196) and recv IO request (offsets +200..+236). Lazy-resolves memset from msvcrt.dll and zeros the 16-byte local address at +4 and the 16-byte remote address at +20. Sets default connection parameters: keepalive interval 1 at +284, idle timeout 90000ms at +288, retransmit base 10000ms at +292. Seeds the PRNG state (g_prng_state) using QueryPerformanceCounter, GetCurrentProcessId, GetCurrentThreadId, and GetTickCount, then generates the 16-byte XOR key at offset +260 by folding these entropy sources with a quadratic mixing function. Returns the struct pointer.

#### transport_cleanup (0x180002054, 304 bytes)

Tears down a transport instance by freeing all associated resources. Closes the send and recv completion event handles at offsets +168 and +208 via g_pfnUnk_5048 (CloseHandle). Iterates the send sequence ring at offset +128: for each occupied slot, frees the data buffer (slot +32) and the slot descriptor, then frees the ring slot array and the ring struct itself. Repeats the same process for the recv sequence ring at offset +136. Frees the send scratch buffer at offset +144 and the recv scratch buffer at offset +152 if non-NULL. Finally deletes the critical section at offset +88 via g_pfnUnk_5010 (DeleteCriticalSection). Does not free the transport struct itself -- the caller (udp_destroy) handles that.

#### transport_config_init (0x180002184, 171 bytes)

Performs post-allocation configuration of the transport state. Registers the transport with the global manager via transport_mgr_register, which assigns a slot ID and sets the initial refcount. Sets default window parameters: send window size 32 at offset +240, recv window size 32 at +244, max outstanding segments 90 at offsets +248 and +252. Allocates two 40-byte sequence ring buffer structures via local_alloc and initializes each with seq_ring_init using the recv window size as capacity -- the send ring is stored at offset +128 and the recv ring at +136. If either ring allocation fails, returns error 8 (ERROR_NOT_ENOUGH_MEMORY). On success, transitions the transport state from UNINITIALIZED (0) to CONFIGURED (1) at offset +256 and returns 0.

#### transport_error_complete (0x1800024BC, 235 bytes)

Completes all pending send and recv IO operations with an error, used during disconnect or fatal error. If the transport is in ESTABLISHED state (5) at offset +256, transitions it to CLOSING (6). For each of the send (offset +160) and recv (offset +200) pending IO requests, if non-NULL: writes 0 to the bytes-transferred field (+20) and the error code to the status field (+28). Signals the corresponding completion event via g_pfnUnk_5088 (SetEvent) and NULLs the pending pointer. The error code is typically 10053 (WSAECONNABORTED) for graceful disconnect or 10054 (WSAECONNRESET) for timeout.

### Sequence Ring Buffer

#### seq_ring_init (0x180001BFC, 105 bytes)

Initializes a sequence ring buffer structure used for ordered packet tracking in the DNS tunnel protocol. The ring struct is 40 bytes: slot pointer array at +0, used count at +8, capacity at +12, low-water sequence at +16, high-water contiguous at +18, max allocated at +20, cumulative size counters at +24 and +32. Allocates the slot pointer array (capacity * 8 bytes) via local_alloc, zeros all entries, and resets all sequence counters to zero. Takes the ring pointer and desired capacity. Returns the ring pointer. Two rings are created per transport: one for send tracking (offset +128) and one for recv reassembly (offset +136).

#### seq_ring_alloc_slot (0x180001C68, 299 bytes)

Allocates a new slot in the sequence ring buffer for a given 16-bit sequence number. Validates that: (1) the sequence is strictly greater than the current high-water mark at ring +18, (2) it does not exceed the window base at ring +16 plus the window size at ring +12, and (3) the slot at index (seq modulo capacity) is not already occupied. Returns 0 immediately on any validation failure. Allocates a 40-byte slot descriptor via local_alloc with fields: seq number at +0, retransmit count at +8, payload offset at +12, payload capacity at +16, data write pointer at +24, and data buffer at +32 (allocated separately with param2 bytes). Updates the ring used count at +8, advances the max-allocated watermark at +20 if needed, and scans forward to update the contiguous high-water mark at +18. Returns the slot descriptor pointer.

#### seq_ring_free_slot (0x180001D94, 178 bytes)

Frees a slot in the sequence ring buffer by 16-bit sequence number. Looks up the slot at index (seq modulo capacity), verifies the stored sequence matches, then accumulates the slot payload size into the ring cumulative counters at +24 and +32 (tracking total bytes sent/received). Frees the data buffer at slot +32, frees the 40-byte slot descriptor, NULLs the ring entry, and decrements the used count at +8. Then scans forward from the current low-water mark (ring +16) to advance it past any contiguous NULL entries, keeping the ring consumption pointer up to date. Returns 0 on success or 4312 if the sequence number does not match or the slot is already empty.

### Send / Receive IO

#### send_complete_check (0x180002230, 125 bytes)

Checks whether the current outbound send operation can make progress and completes it if done. If a send request is pending (offset +160 non-NULL), calls send_drain_next_segment to copy the next chunk of data from the send ring buffer into the IO buffer. If drain returns WSAEWOULDBLOCK (10035), treats it as a non-error (the ring is temporarily empty but more data may arrive). For any other error, or if the bytes-transferred counter (IO +24) exceeds zero, signals completion: copies bytes-transferred into the IO result field (+20), stores the error code at +28, signals the send event via g_pfnUnk_5088 (SetEvent), and clears the pending pointer at offset +160. Returns 0 unconditionally.

#### recv_fill_segments (0x1800022B0, 339 bytes)

Reassembles received data from the recv ring buffer into the pending recv IO request. If a recv request is active (offset +200 non-NULL), loops over consecutive sequence slots in the recv ring (offset +128), starting from the ring consumption pointer (+20). For each slot, copies min(remaining_in_slot, remaining_in_user_buffer) bytes via memcpy_wrapper, advancing both the slot read cursor (+12) and the IO buffer write cursor (+24). When a slot has no more data and the next sequence is beyond the window, allocates a new slot via seq_ring_alloc_slot with the max outstanding limit from offsets +248/+252. If slot allocation fails, completes with error 8. Once the user buffer is full (IO +24 >= IO +16), or on error, signals completion by writing bytes-transferred and status to the IO descriptor and firing the recv event. Clears the pending recv pointer at offset +200.

#### send_drain_next_segment (0x180002404, 181 bytes)

Drains the next outbound data segment from the send ring buffer into the send IO buffer. Reads the send ring (offset +136) and looks up the slot for sequence = low_water + 1 (ring +16). If no slot exists at that sequence, returns 10035 (WSAEWOULDBLOCK), indicating no data is available yet. Otherwise copies min(remaining_in_slot, remaining_in_IO_buffer) bytes via memcpy_wrapper from the slot data buffer (slot +24 + slot +12) to the IO buffer (param1 +8 + param1 +24), advancing both read cursors. If the slot is fully consumed (slot +12 >= slot +16), calls seq_ring_free_slot to release it. Returns 0 on success.

### Utility / Memory

#### local_alloc (0x18000167C, 54 bytes)

Wrapper that lazy-resolves and calls LocalAlloc(LMEM_ZEROINIT, size). On first call, resolves the address of kernel32!LocalAlloc via resolve_export_by_hash with hash 0x95E0B854 (ROR8+XOR algorithm) and caches it in g_pfnLocalAlloc. Subsequent calls use the cached pointer directly. Passes LMEM_ZEROINIT (0x40) as the flags parameter, ensuring all returned memory is zero-filled. Takes the allocation size as the sole parameter and returns the pointer to the allocated block, or NULL on failure. Used throughout the DNS plugin for all heap allocations.

#### local_free (0x1800016B4, 53 bytes)

Wrapper that lazy-resolves and calls LocalFree on the given pointer. Performs a NULL check first and returns immediately if the pointer is NULL. On first call, resolves kernel32!LocalFree via resolve_export_by_hash with hash 0xF327A303 and caches it in g_pfnLocalFree. All subsequent calls use the cached function pointer. Takes a single pointer parameter. This is the counterpart to local_alloc and is used throughout the DNS plugin for all heap deallocations.

#### memcpy_wrapper (0x180001AE4, 120 bytes)

Wrapper around the CRT memcpy function from msvcrt.dll. On first call, decrypts the string "memcpy" via decrypt_string, converts it to multibyte via wchar_to_multibyte, resolves it from msvcrt.dll via resolve_dll_export, and caches the pointer in g_pfnmemcpy. All subsequent calls use the cached pointer directly. Takes destination, source, and byte count parameters in the standard memcpy calling convention. Returns the destination pointer. Used extensively throughout the DNS plugin for buffer copies in ring buffer operations and packet construction.

#### decrypt_string (0x180003E58, 185 bytes)

Decrypts an encrypted string blob using the ScatterBrain IMUL PRNG XOR cipher. Allocates a 4096-byte temporary buffer, reads a 2-byte little-endian seed from the encrypted blob, then XOR-decrypts each subsequent byte using the PRNG state: state = -42860544 * state - 135791246 * HIWORD(state) - 1043215206 (the standard ScatterBrain IMUL cipher). Decryption stops on a null terminator or after 4090 bytes. Initializes the 28-byte output string descriptor (out_str) with zero fields: multibyte pointer at +0, multibyte length at +8, widechar pointer at +16, widechar length at +24. Calls multibyte_to_wchar to convert the decrypted UTF-8 bytes to UTF-16 and store both representations in the descriptor. Frees the temporary buffer. Returns the out_str pointer.

#### decrypt_string_cleanup (0x180003F14, 59 bytes)

Frees both string representations held by a decrypted string descriptor. If the multibyte buffer at offset +0 is non-NULL, frees it via local_free, NULLs the pointer, and zeros the length at +8. If the widechar buffer at offset +16 is non-NULL, frees it, NULLs the pointer, and zeros the length at +24. Called after each string decryption operation to prevent memory leaks, since encrypted strings are decrypted on-demand and the buffers are transient.

#### wchar_to_multibyte (0x180003F50, 188 bytes)

Converts a wide-character (UTF-16) string to multibyte (ANSI/system codepage). Lazy-resolves kernel32!WideCharToMultiByte via API hash 0x991B4E4E and caches it. Calls WideCharToMultiByte twice: first with NULL output to determine the required buffer size, then allocates via local_alloc and performs the actual conversion. Reads the widechar string from the descriptor at offset +16 with length at +24. If a previous multibyte buffer exists at offset +0, frees it first. Stores the new multibyte buffer at +0 and its byte length at +8. Returns the multibyte pointer, or NULL/0 on allocation failure. Used after decrypt_string to produce the multibyte representation needed by resolve_dll_export.

#### multibyte_to_wchar (0x18000400C, 233 bytes)

Converts a multibyte (UTF-8, codepage 65001) string to wide-character (UTF-16). Lazy-resolves kernel32!MultiByteToWideChar via API hash 0xB8DE5C78 and caches it. Calls MultiByteToWideChar twice: first with NULL output to get the required buffer size in WCHARs, allocates size*2 bytes via local_alloc, then performs the conversion. Frees any existing multibyte buffer at descriptor +0 and widechar buffer at +16 before storing the new widechar buffer at +16 and its WCHAR count at +24. Returns 0 on success or 8 on allocation failure. Called by decrypt_string to convert freshly decrypted UTF-8 bytes into the UTF-16 representation stored in the string descriptor.

#### Dynamic Buffer (dynbuf)

#### dynbuf_reset (0x180003D60, 52 bytes)

Resets a dynamic buffer logical size to the specified value. The dynbuf structure has 4 fields: logical size at +0, allocated capacity at +4, write cursor at +8, and data pointer at +16. If the requested size exceeds the current capacity, calls dynbuf_grow to expand the buffer first. If the write cursor at +8 exceeds the new size, clamps it down. Returns 0 on success or the error code from dynbuf_grow on allocation failure. Used to prepare buffers for reuse without freeing, and to pre-allocate known-size buffers before dns_encode_payload fills them.

#### dynbuf_append (0x180003D94, 99 bytes)

Appends data to a dynamic buffer at the current write cursor position. Checks if the current write cursor (offset +8) plus the new data size exceeds the allocated capacity (offset +4); if so, calls dynbuf_grow to expand by at least 4096 bytes beyond the needed total. Copies param2 bytes from the source pointer to the data buffer (offset +16) at the write cursor offset, advances the write cursor by param2, and updates the logical size at +0 if the cursor has advanced past it. Returns 0 on success or the error from dynbuf_grow on allocation failure. This is the primary data accumulation function used during DNS packet construction.

#### dynbuf_grow (0x180003DF8, 96 bytes)

Grows a dynamic buffer to at least the specified capacity. Allocates a new buffer of the requested size via local_alloc (which zero-initializes), copies the current logical contents (size at +0 bytes) from the old buffer via memcpy_wrapper, frees the old buffer at +16 if non-NULL, stores the new buffer pointer at +16, and updates the capacity at +4. Returns 0 on success or 8 (ERROR_NOT_ENOUGH_MEMORY) on allocation failure. Called by dynbuf_append and dynbuf_reset when the current capacity is insufficient.
