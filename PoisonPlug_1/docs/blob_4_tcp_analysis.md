# Blob 4 — Raw TCP + DNS Sockets Plugin ("TCP")

## Summary

| Property | Value |
|----------|-------|
| File | Private archive artifact (available on vetted request) |
| Image Size | 0x5000 (20480 bytes) |
| Entry Point RVA | 0x123C |
| Functions | 23 (all renamed) |
| Sections | .text, .rdata, .data2, .data3, .idata |
| Timestamp | 0x58AEBA (2017-02-22/23) |
| idasql Port | 8204 |
| Version (CMD 102) | 200 |
| Plugin Name (CMD 103) | `"TCP"` (encrypted at `0x1800030C0`) |
| Plugin Vtable | 6 slots |

## Role

**Raw TCP socket transport with proxy support.** The smallest plugin (23 functions). Provides fundamental network I/O: TCP socket creation, four connection modes (direct, SOCKS4, SOCKS5, HTTP CONNECT), and send/recv operations. Implements custom DNS resolution via `dnsapi.dll` to bypass system DNS.

## Imports (21 functions, 3 DLLs)

### KERNEL32.dll (5)
lstrcpyW, GetComputerNameA, lstrlenA, LoadLibraryA, GetProcAddress

### USER32.dll (1)
wsprintfA

### WS2_32.dll (15 by ordinal + WSAIoctl)
WSACleanup(116), WSAStartup(115), socket(23), WSAGetLastError(111), WSAIoctl, htons(9), ioctlsocket(10), connect(4), select(18), recv(16), shutdown(22), closesocket(3), setsockopt(21), send(19), gethostbyname(52)

## Entry Point: sb_plugin_entry (0x18000123C)

| fdwReason | Command | Action |
|-----------|---------|--------|
| 0 | DETACH | No-op |
| 1 | ATTACH | Populates 6-slot vtable at `0x180004008` |
| 100 | START | `WSAStartup(MAKEWORD(1,1))` |
| 101 | STOP | `WSACleanup()` |
| 102 | VERSION | Returns 200 |
| 103 | NAME | Decrypts "TCP", copies via lstrcpyW |
| 104 | VTABLE | Returns `&vtable (0x180004000)` |

## Vtable (6 slots)

| Slot | Offset | Address | Name | Purpose |
|------|--------|---------|------|---------|
| 0 | +0x08 | 0x180001000 | `vtbl_create_socket` | Allocate 112-byte context, create TCP socket, set keepalive |
| 1 | +0x10 | 0x180001110 | `vtbl_dispatch_connect` | Mode switch: direct/SOCKS4/SOCKS5/HTTP |
| 2 | +0x18 | 0x18000118C | `vtbl_recv` | Validate socket, delegate to recv_raw |
| 3 | +0x20 | 0x1800011B0 | `vtbl_send` | Validate socket, delegate to send_raw |
| 4 | +0x28 | 0x1800011D4 | `vtbl_shutdown` | `shutdown(sock, SD_BOTH)` |
| 5 | +0x30 | 0x1800011FC | `vtbl_close_and_free` | Shutdown + closesocket + LocalFree |

## Connection Context (112 bytes / 0x70)

| Offset | Type | Value | Meaning |
|--------|------|-------|---------|
| 0x00 | DWORD | 1 | Protocol type (TCP) |
| 0x58 | QWORD | -1 | Socket handle (INVALID_SOCKET) |
| 0x60 | 4xDWORD | from cmd | Custom DNS server IPs |

## Connect Command Buffer Layout

```
+0x000: WORD   port
+0x004: WORD   address_family
+0x006: WORD   mode (0=direct, 1=SOCKS4, 2=SOCKS5, 3=HTTP CONNECT)
+0x008: char[0x400]  target hostname
+0x408: char[0x400]  proxy hostname
+0x808: char[0x400]  proxy username (SOCKS5)
+0xC08: char[0x400]  proxy password (SOCKS5)
+0x1008: DWORD[4]    custom DNS server IPs
```

## Connection Modes

### Mode 0: Direct TCP (`tcp_connect_with_dns`, 0x180001530, 785 bytes)
1. Check for custom DNS servers in command buffer
2. If custom DNS: `DnsQuery_A(host, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, &servers, &result, 0)`
3. Fallback: `gethostbyname(hostname)`
4. Non-blocking connect: `ioctlsocket(FIONBIO, 1)` -> `connect` -> `select(10s timeout)` -> `ioctlsocket(FIONBIO, 0)`
5. Re-apply SIO_KEEPALIVE_VALS after connect

### Mode 1: SOCKS4 (`connect_via_socks4`, 0x180001844, 686 bytes)
1. Connect to proxy via `tcp_connect_with_dns`
2. Resolve target hostname
3. Build SOCKS4 request: `[0x04, 0x01, port_hi, port_lo, IP[4], GetComputerNameA()...]`
4. Validate response: `buf[0]==0x00 && buf[1]==0x5A` (request granted)
5. **Note**: Computer name sent as SOCKS4 userid — victim identification leak

### Mode 2: SOCKS5 (`connect_via_socks5`, 0x180001AF4, 474 bytes)
1. Connect to proxy
2. Greeting: `[0x05, 0x02, 0x00, 0x02]` (no-auth + username/password)
3. If auth required: `[0x01, ulen, username..., plen, password...]`
4. CONNECT: `[0x05, 0x01, 0x00, 0x03, hostname_len, hostname..., port_hi, port_lo]`
5. Address type 0x03 = domain name (proxy resolves)

### Mode 3: HTTP CONNECT (`connect_via_http_proxy`, 0x180001CD0, 760 bytes)
```
CONNECT %s:%d HTTP/1.0\r\n
Host: %s\r\n
Proxy-Connection: Keep-Alive\r\n
Pragma: no-cache\r\n
\r\n
```
Validates response: `HTTP/1.0 200 ` or `HTTP/1.1 200 ` via memcmp.

## TCP Keepalive (Anti-Timeout)
Applied at socket creation and after connect:
- `SIO_KEEPALIVE_VALS` (0x98000004)
- onoff=1, keepalivetime=60000ms, keepaliveinterval=1000ms
- Prevents NAT/firewall idle connection drops

## Send/Recv Implementation
- `send_raw` / `recv_raw`: Single call with SO_SNDTIMEO/SO_RCVTIMEO (60s default)
- `send_all` / `recv_all`: Loop until all bytes transferred or error
- Return `WSAECONNRESET` (10054) if send/recv returns 0
- Timeout of -1 means infinite retry on WSAETIMEDOUT

## Encrypted Strings (13 total)

| Address | Decrypted | Used For |
|---------|-----------|----------|
| 0x1800030C0 | `TCP` | Plugin name |
| 0x1800030C8 | `msvcrt.dll` | DLL for memcmp |
| 0x1800030D8 | `CONNECT %s:%d HTTP/1.0\r\n` | HTTP proxy request |
| 0x1800030F8 | `Host: %s\r\n` | HTTP proxy header |
| 0x180003108 | `Proxy-Connection: Keep-Alive\r\n` | HTTP proxy header |
| 0x180003130 | `Pragma: no-cache\r\n` | HTTP proxy header |
| 0x180003148 | `\r\n` | Header terminator |
| 0x180003150 | `HTTP/1.0 200 ` | Success check |
| 0x180003168 | `HTTP/1.1 200 ` | Success check |
| 0x180003180 | `dnsapi.dll` | DNS resolution DLL |
| 0x180003190 | `DnsQuery_A` | DNS query API |
| 0x1800031A0 | `DnsRecordListFree` | DNS cleanup API |
| 0x1800031B8 | `memcmp` | Response validation |

## Key Behaviors

1. **Custom DNS bypass**: Up to 4 operator-specified DNS servers via `DnsQuery_A` with `DNS_QUERY_BYPASS_CACHE`, completely bypassing system DNS resolver and monitoring.
2. **SOCKS4 computer name leak**: Computer name sent as SOCKS4 userid — operator identification at proxy layer.
3. **Non-blocking connect with select**: 10-second timeout, graceful error handling.
4. **Four proxy modes**: Maximum flexibility to traverse network controls.
5. **Total API count**: 21 static + 6 PEB-resolved + 3 dynamic = 30 APIs.

## Detailed Function Reference

All 23 functions in the TCP transport plugin, grouped by functional category.

---

### API Resolution

#### peb_resolve_export (0x18000139C, 241 bytes)

PEB-walking API hash resolver that locates exported functions from kernel32.dll without using GetProcAddress. Traverses the InLoadOrderModuleList from the PEB Ldr structure, computing a rolling ROR8+XOR hash (constant 0x7C35D9A3) over each module BaseDllName (case-insensitive via OR 0x20). Identifies kernel32.dll by its hash value 0xFD5718A1 (two-complement -44363167). Once the module base is found, parses its PE export directory to enumerate all exported function names, computing the same ROR8+XOR hash over each name. When a name hash matches the input parameter, the corresponding function address is resolved through the ordinal table and AddressOfFunctions array. Returns the resolved function pointer, or NULL if the hash is not found or the export count is zero. This is the foundational resolution primitive used by heap_alloc, heap_free, wchar_to_ansi, ansi_to_wchar, and resolve_dll_proc.

#### resolve_dll_proc (0x180001490, 159 bytes)

Resolves an arbitrary exported function from msvcrt.dll by name. On first invocation, decrypts the string `msvcrt.dll` using the IMUL cipher, converts it from wide-char to ANSI, then calls LoadLibraryA (resolved via peb_resolve_export with HASH_LoadLibraryA) to load the C runtime DLL, caching the module handle in g_pfnmsvcrt_dll_2. Subsequently resolves GetProcAddress via peb_resolve_export (HASH_GetProcAddress), caching it in g_hModule_dll. Finally calls GetProcAddress(msvcrt_handle, function_name) to obtain the target function pointer. The input parameter is an ANSI function name string (e.g., `memcmp`, `strlen`). This two-level lazy initialization pattern ensures both the DLL handle and GetProcAddress are resolved only once. Used by connect_via_http_proxy to resolve memcmp for HTTP response validation.

---

### Plugin Protocol / Dispatch

#### sb_plugin_entry (0x18000123C, 239 bytes)

Plugin entry point and DllMain dispatcher for the TCP transport plugin (ID 200). Handles multiple fdwReason commands from the ScatterBrain plugin loader: reason 1 populates the 6-entry sb_transport_vtable_t at g_tcp_vtable with function pointers (create_socket, dispatch_connect, recv, send, shutdown, close_and_free). Reason 100 calls WSAStartup with version 2.2 (0x0101) to initialize Winsock. Reason 101 calls WSACleanup to tear down Winsock. Reason 102 writes the plugin version number 200 to the output pointer. Reason 103 decrypts the plugin name string "TCP" using the IMUL cipher and copies it to the caller-supplied buffer via strcpy. Reason 104 writes a pointer to the populated g_tcp_vtable into the output location, allowing the host to invoke transport operations through the vtable. The function always returns TRUE (1) regardless of the command processed.

---

### Socket Operations

#### tcp_connect_with_dns (0x180001530, 785 bytes)

Establishes a direct TCP connection to a remote host with custom DNS resolution support. Accepts a hostname, port (16-bit big-endian), and an array of up to 4 custom DNS server IP addresses. First attempts name resolution using DnsQuery_A from dnsapi.dll (lazily loaded via LoadLibraryA and GetProcAddress, with the library name and function names decrypted via IMUL cipher). The DNS query is type A (1) with flags 0x40 (DNS_QUERY_BYPASS_CACHE), passing the custom DNS server list. If custom DNS succeeds and returns an A record (type 1), the resolved IPv4 address is extracted from the DNS_RECORD at offset +32. If custom DNS is unavailable or fails, falls back to the standard getaddrinfo resolution via g_pfnTCP. The connection itself uses a non-blocking socket pattern: ioctlsocket sets FIONBIO mode, connect is called (WSAEWOULDBLOCK/10035 is expected), then ioctlsocket clears non-blocking mode, and select() with a 10-second timeout polls for writability. If select returns 0 (timeout), error 10060 (WSAETIMEDOUT) is returned. After a successful connection, SIO_KEEPALIVE_VALS is re-applied with the same 60s/1s parameters as socket creation.

#### send_raw (0x180001FC8, 165 bytes)

Low-level send primitive for the TCP transport. Configures the socket send timeout by calling setsockopt with SO_SNDTIMEO (option 4101 at level SOL_SOCKET/0xFFFF). If the caller passes timeout -1, it defaults to 60000ms (60 seconds). Calls send() via g_pfnUnk_30A8 with the socket handle from context+88, the data buffer, byte count, and flags=0. The bytes actually sent are written to the output pointer. If send() returns a negative value (error), WSAGetLastError is called; if the error is WSAETIMEDOUT (10060) and the timeout was the infinite sentinel (-1), the send is automatically retried in a loop, making infinite-timeout sends resilient to transient timeouts. If send() returns 0 (connection gracefully closed), the function returns 0x2746 (WSAEDISCON/10054). Returns 0 on a successful send with positive byte count. This function is called by send_all for reliable delivery and by vtbl_send for single-shot sends.

#### send_all (0x180002070, 115 bytes)

Reliable send function that guarantees delivery of all requested bytes over the TCP transport. Takes the transport context, source buffer pointer, and total byte count to send. Loops calling send_raw with an infinite timeout (-1) on each iteration, advancing the buffer position and decrementing the remaining count by the number of bytes actually sent each round. Before each iteration, checks that the socket handle at context+88 is still valid (not INVALID_SOCKET/-1); if the socket has been closed, returns WSAENOTSOCK (10038). If send_raw returns any nonzero error code, that error is immediately propagated to the caller. Returns 0 only when all bytes have been successfully transmitted. If the byte count is zero or negative, returns 0 immediately without sending. Used by the SOCKS4, SOCKS5, and HTTP CONNECT proxy negotiation functions, as well as any higher-level protocol that needs to send a complete message atomically.

#### recv_raw (0x1800020E4, 165 bytes)

Low-level receive primitive for the TCP transport. Configures the socket receive timeout by calling setsockopt with SO_RCVTIMEO (option 4102 at level SOL_SOCKET/0xFFFF). If the caller passes timeout -1, it defaults to 60000ms (60 seconds). Calls recv() via g_pfnUnk_3088 with the socket handle from context+88, the destination buffer, maximum byte count, and flags=0. The bytes actually received are written to the output pointer. If recv() returns a negative value (error), WSAGetLastError is called; if the error is WSAETIMEDOUT (10060) and the timeout was the infinite sentinel (-1), the receive is automatically retried in a loop, providing resilience against transient timeouts during long-running transfers. If recv() returns 0 (remote end closed connection gracefully), the function returns 0x2746 (WSAEDISCON/10054). Returns 0 on a successful receive with positive byte count. This function is the symmetric counterpart to send_raw and is called by recv_all and vtbl_recv.

#### recv_all (0x18000218C, 115 bytes)

Reliable receive function that guarantees reception of exactly the requested number of bytes from the TCP transport. Takes the transport context, destination buffer pointer, and total byte count to receive. Loops calling recv_raw with an infinite timeout (-1) on each iteration, advancing the buffer position and decrementing the remaining count by the number of bytes actually received each round. Before each iteration, checks that the socket handle at context+88 is still valid (not INVALID_SOCKET/-1); if the socket has been closed, returns WSAENOTSOCK (10038). If recv_raw returns any nonzero error code (including WSAEDISCON/0x2746 for graceful close), that error is immediately propagated to the caller. Returns 0 only when all requested bytes have been successfully received. If the byte count is zero or negative, returns 0 immediately. This is the symmetric counterpart to send_all and is used by SOCKS4, SOCKS5, and HTTP CONNECT proxy negotiation to receive fixed-length protocol responses.

---

### Proxy Support (SOCKS4, SOCKS5, HTTP CONNECT)

#### connect_via_socks4 (0x180001844, 686 bytes)

Connects to a target host through a SOCKS4 proxy server (RFC 1928 predecessor). First establishes a TCP connection to the proxy server itself by calling tcp_connect_with_dns with the proxy address (config+1032), proxy port (config+4, 16-bit), and DNS servers (config+4104). Then resolves the target hostname to an IPv4 address using the same custom DNS resolution strategy as tcp_connect_with_dns: tries DnsQuery_A with up to 4 configured DNS servers first, falls back to getaddrinfo. Constructs a SOCKS4 CONNECT request in a 1024-byte heap buffer: version byte 0x04, command 0x01 (CONNECT), destination port in big-endian (from config+0/+1), destination IP (4 bytes), and a user ID string copied from the machine's computer name via GetComputerNameA followed by strcpy. Sends the complete request via send_all, then receives the 8-byte SOCKS4 reply via recv_all. Validates the reply: byte 0 must be 0x00 (null) and byte 1 must be 0x5A (90 decimal, meaning request granted). If either check fails, the function returns error code 50. Notable: the computer name is sent as the SOCKS4 userid, creating a victim identification leak at the proxy layer.

#### connect_via_socks5 (0x180001AF4, 474 bytes)

Connects to a target host through a SOCKS5 proxy server (RFC 1928/1929). First establishes a TCP connection to the proxy server via tcp_connect_with_dns using the proxy address at config+1032 and proxy port at config+4. Allocates a 1024-byte negotiation buffer and performs the three-phase SOCKS5 handshake. Phase 1 (greeting): sends version 5 with two supported methods (0x00=no authentication, 0x02=username/password). Phase 2 (authentication): if the server selects method 0x02, constructs an RFC 1929 username/password subnegotiation packet (version 0x01, username from config+2056 with length prefix, password from config+3080 with length prefix) and validates the server accepts (status byte 0x00). If method 0x00 is selected, skips authentication. Phase 3 (connect request): builds a CONNECT command (version 5, command 1, reserved 0, address type 0x03=domain name) with the target hostname from config+8 (length-prefixed), followed by the target port in big-endian from config+0/+1. Sends via send_all and receives the server response via recv_all. If any phase returns an error or authentication is rejected, error code 50 is returned.

#### connect_via_http_proxy (0x180001CD0, 760 bytes)

Connects to a target host through an HTTP CONNECT proxy. First establishes a TCP connection to the proxy server via tcp_connect_with_dns using the proxy address at config+1032 and proxy port at config+4. Allocates a 4096-byte buffer and constructs a multi-line HTTP CONNECT request by decrypting and concatenating several IMUL-encrypted format strings: the CONNECT method line (target host:port), a Host header, a Proxy-Connection: Keep-Alive header, a Pragma: no-cache header, and a final CRLF to terminate the headers. Each string is decrypted, converted from wide-char to ANSI, and appended via strcpy. The complete request is sent via send_all. The HTTP response is then read byte-by-byte using recv() directly, scanning for the CRLFCRLF (0x0D 0x0A 0x0D 0x0A) header terminator, with a safety limit of 4096 bytes and a minimum of 13 bytes before checking. Once headers are received, the response status is validated by comparing the first 13 bytes against two decrypted reference strings ("HTTP/1.0 200 " and "HTTP/1.1 200 ") using memcmp (resolved dynamically from msvcrt.dll via resolve_dll_proc). If neither matches, the function returns error code 50.

---

### Custom DNS Resolution

#### vtbl_dispatch_connect (0x180001110, 121 bytes)

Central connection dispatcher that routes outbound connections through the appropriate proxy protocol. First copies up to 4 custom DNS server IP addresses from the configuration structure (at config+4008) into the transport context at offset +96, building a DNS server array for subsequent resolution. Then switches on the proxy type field at config+6 (a 16-bit value): type 0 performs a direct TCP connection via tcp_connect_with_dns, type 1 tunnels through a SOCKS4 proxy via connect_via_socks4, type 2 tunnels through a SOCKS5 proxy via connect_via_socks5, and type 3 tunnels through an HTTP CONNECT proxy via connect_via_http_proxy. For direct connections (type 0), the target hostname is at config+8, port at config+0 (16-bit big-endian), and the DNS server list at config+4104. If the proxy type is unrecognized (not 0-3), the function returns error code 50.

---

### Transport Vtable Functions

#### vtbl_create_socket (0x180001000, 271 bytes)

Allocates and initializes a 112-byte TCP transport context structure on the heap via LocalAlloc(LPTR). The socket handle is stored at context+88 and initialized to INVALID_SOCKET (-1). Fields at offsets +36, +48, +56, +64, and +72 are zeroed, and a protocol identifier of 1 is stored at offset +0. If a pre-existing socket is passed via param2 and is valid (not NULL or -1), it is adopted directly; otherwise a new socket is created via the inner PE callback at g_pfnUnk_3050(AF_INET=2). After obtaining a valid socket, the function configures TCP keepalive using WSAIoctl with SIO_KEEPALIVE_VALS (ioctl code 0x98000004): keepalive enabled, 60-second interval, 1-second retry. On any socket creation failure, WSAGetLastError is returned and the allocated context is freed. The output pointer (*this_ptr) receives the context address and the function returns 0 on success.

#### vtbl_recv (0x18000118C, 36 bytes)

Receive wrapper that provides socket validity checking before delegating to recv_raw. Reads the socket handle from the transport context at offset +88 and returns WSAENOTSOCK (error 10038) immediately if it is INVALID_SOCKET (-1), preventing any Winsock calls on a closed or uninitialized socket. Otherwise, forwards all parameters directly to recv_raw: the transport context, destination buffer, buffer size, output byte-count pointer, and timeout value. The return value is 0 on success, or a Winsock error code on failure (including 0x2746/WSAEDISCON if the remote end closed the connection gracefully). This guard pattern is consistent across all vtable I/O slots.

#### vtbl_send (0x1800011B0, 36 bytes)

Send wrapper that provides socket validity checking before delegating to send_raw. Reads the socket handle from the transport context at offset +88 and returns WSAENOTSOCK (error 10038) immediately if it is INVALID_SOCKET (-1), preventing any Winsock calls on a closed or uninitialized socket. Otherwise, forwards all parameters directly to send_raw: the transport context, source buffer, byte count, output bytes-sent pointer, and timeout value. The return value is 0 on success, or a Winsock error code on failure (including 0x2746/WSAEDISCON if send returns zero bytes). This guard pattern mirrors vtbl_recv and ensures consistent error handling across the transport interface.

#### vtbl_shutdown (0x1800011D4, 40 bytes)

Initiates a graceful TCP shutdown on the transport socket. Calls shutdown() with SD_BOTH (how=2) on the socket handle stored at context+88 to disable both send and receive operations. If shutdown() returns a nonzero error indicator, calls WSAGetLastError to retrieve the specific Winsock error code and returns it. Returns 0 on success. This function does not close the socket or free resources; it only signals the transport layer that no more data will be sent or received. The actual socket closure and context deallocation are handled by vtbl_close_and_free (vtable slot 5).

#### vtbl_close_and_free (0x1800011FC, 61 bytes)

Performs full teardown of the TCP transport context. First checks if the socket handle at context+88 is valid (not INVALID_SOCKET/-1); if so, calls shutdown(socket, SD_BOTH) to gracefully terminate the connection, then calls closesocket() to release the socket resource, and sets the handle back to INVALID_SOCKET. Finally, calls heap_free (LocalFree) to deallocate the entire 112-byte transport context structure, and returns 0. This is the destructor for TCP transport objects and must be called to prevent socket and memory leaks. The function is safe to call even if the socket was never successfully created, as it guards against INVALID_SOCKET.

---

### Utility / Memory

#### heap_alloc (0x18000132C, 54 bytes)

Heap allocation wrapper used throughout the TCP plugin. Lazily resolves the LocalAlloc API function via PEB-walking export hash resolution (peb_resolve_export with HASH_LocalAlloc) on first call, caching the resolved pointer in g_pfnHeapAlloc for subsequent invocations. Calls LocalAlloc with flags LPTR (0x40), which combines LMEM_FIXED and LMEM_ZEROINIT, guaranteeing the returned buffer is zero-initialized. Takes a single size parameter specifying the number of bytes to allocate. Returns the pointer to the allocated memory block, or NULL if allocation fails. This function is the sole allocator for all dynamic memory in the plugin, including transport context structures, proxy negotiation buffers, and string decryption temporaries.

#### heap_free (0x180001364, 53 bytes)

Heap deallocation wrapper used throughout the TCP plugin. Lazily resolves the LocalFree API function via PEB-walking export hash resolution (peb_resolve_export with HASH_LocalFree) on first call, caching the resolved pointer in g_pfnHeapFree for subsequent invocations. Takes a single pointer parameter and calls LocalFree to release the memory. Includes a NULL guard: if the input pointer is NULL, the function returns immediately without attempting to free, preventing access violations. This is the counterpart to heap_alloc and is used to free transport contexts, proxy negotiation buffers, decrypted string temporaries, and all other dynamically allocated memory in the plugin.

#### decrypt_string (0x180002200, 215 bytes)

Decrypts an IMUL-cipher encrypted string blob and returns a dual-format string pair structure. Allocates a 4096-byte temporary buffer via heap_alloc. Reads a 16-bit seed key from the first 2 bytes of the encrypted blob (little-endian), then iterates over the remaining cipher bytes, XORing each with the low byte of the evolving key state. The key state is advanced using a polynomial PRNG: `key = key * -42860544 - HIWORD(key) * 135791246 - 1043215206` (IMUL-based multiply-subtract scheme). Decryption terminates when a null byte is produced or the 4090-byte safety limit is reached. The decrypted ANSI string in the temporary buffer is then converted to wide-char (UTF-16LE) via ansi_to_wchar, which populates the output string pair structure with both ANSI (offset +0, length at +8) and wide-char (offset +16, length at +24) representations. The temporary decryption buffer is freed via LocalFree before returning. Returns the out_str pointer for convenient chaining. Called extensively to decrypt API names, HTTP header templates, and the plugin name string.

#### free_str_pair (0x1800022D8, 59 bytes)

Frees both buffers in a dual-format string pair structure produced by decrypt_string. The string pair structure is 28 bytes with two slots: the ANSI string pointer at offset +0 with its length at offset +8, and the wide-char string pointer at offset +16 with its length at offset +24. For each slot, checks if the pointer is non-NULL, calls heap_free (LocalFree) to release the buffer, then zeros both the pointer and length fields to prevent use-after-free. Called after every decrypt_string usage to clean up temporary decrypted strings, particularly in tcp_connect_with_dns (DNS API names), connect_via_socks4/socks5 (DNS API names), connect_via_http_proxy (HTTP header templates and memcmp), and resolve_dll_proc (msvcrt.dll name). The two-phase cleanup (ANSI then wide-char) ensures no memory is leaked regardless of which conversion steps completed.

#### wchar_to_ansi (0x180002314, 188 bytes)

Converts the wide-char (UTF-16LE) string in a string pair structure to an ANSI (multi-byte) string. Lazily resolves WideCharToMultiByte from kernel32.dll via peb_resolve_export (HASH_WideCharToMultiByte), caching the function pointer in g_pfnUnk_4090. Uses the standard two-call pattern: first calls WideCharToMultiByte with codepage 0 (CP_ACP), the wide-char buffer from offset +16, its length from offset +24, and NULL output buffer to determine the required ANSI buffer size. Then allocates a buffer of that size via heap_alloc and calls WideCharToMultiByte again to perform the actual conversion. If the ANSI slot (offset +0) already contains a buffer, it is freed via heap_free and the pointer and length are zeroed before storing the new ANSI string. The new ANSI pointer is stored at offset +0 and its length at offset +8. Returns the ANSI buffer pointer on success, or NULL on allocation failure. This function is the inverse of ansi_to_wchar and is used to produce ANSI strings for Winsock API calls and strcpy operations.

#### ansi_to_wchar (0x1800023D0, 233 bytes)

Converts an ANSI (UTF-8) string to wide-char (UTF-16LE) and stores it in a string pair structure. Lazily resolves MultiByteToWideChar from kernel32.dll via peb_resolve_export (HASH_MultiByteToWideChar), caching the function pointer in g_pfnUnk_4098. Uses codepage 65001 (CP_UTF8) for the conversion, indicating the input is expected to be UTF-8 encoded. Employs the standard two-call pattern: first calls MultiByteToWideChar with a NULL-terminated input (length -1) and NULL output to get the required wide-char count, then allocates a buffer of count*2 bytes via heap_alloc (using saturated_mul to prevent integer overflow), and calls MultiByteToWideChar again to perform the conversion. Before storing results, frees any existing ANSI buffer at offset +0 and wide-char buffer at offset +16, zeroing their pointers and lengths. The new wide-char pointer is stored at offset +16 and the character count at offset +24. Returns 0 on success, or 8 (ERROR_NOT_ENOUGH_MEMORY) on allocation failure. This is the primary conversion function used by decrypt_string to produce wide-char output from decrypted ANSI plaintext.
