#!/usr/bin/env python
"""
recover_source.py -- Recover clean C source from ScatterBrain plugin IDBs via idasql.

Usage:
    python scripts/recover_source.py --blob N [--port PORT] [--skip-launch]
    python scripts/recover_source.py --blob -1  # process all blobs sequentially
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import requests

# Force UTF-8 stdout on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDASQL = os.environ.get("IDASQL_PATH", "idasql")

BLOB_META = {
    0: {"name": "Install",  "port": 8200, "funcs": 50, "role": "Token theft + anti-analysis"},
    1: {"name": "Plugins",  "port": 8201, "funcs": 34, "role": "Registry CRUD persistence"},
    2: {"name": "Config",   "port": 8202, "funcs": 27, "role": "Config management + file I/O"},
    3: {"name": "Online",   "port": 8203, "funcs": 55, "role": "System recon + C2 router"},
    4: {"name": "TCP",      "port": 8204, "funcs": 23, "role": "Raw TCP + DNS socket transport"},
    5: {"name": "HTTP",     "port": 8205, "funcs": 42, "role": "HTTP POST transport + WinInet"},
    6: {"name": "UDP",      "port": 8206, "funcs": 55, "role": "Reliable UDP (RUDP) transport"},
    7: {"name": "DNS",      "port": 8207, "funcs": 51, "role": "DNS tunnel transport"},
}


def sql(port, query, timeout=60):
    """Execute SQL against idasql HTTP server."""
    url = f"http://127.0.0.1:{port}/query"
    try:
        r = requests.post(url, data=query, timeout=timeout)
        r.raise_for_status()
        j = r.json()
        ok = j.get("success")
        if ok is None:
            ok = "error" not in j
        if not ok:
            print(f"  SQL err: {j.get('error','?')[:100]} | {query[:100]}", file=sys.stderr)
            return None
        return j
    except Exception as e:
        print(f"  Req fail: {e} | {query[:80]}", file=sys.stderr)
        return None


def wait_for_server(port, max_wait=90):
    """Wait for idasql HTTP server to become ready."""
    print(f"  Waiting for idasql on port {port}...", flush=True)
    start = time.time()
    while time.time() - start < max_wait:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/status", timeout=3)
            if r.status_code == 200:
                info = r.json()
                print(f"  Server ready: {info.get('functions', '?')} functions")
                return True
        except:
            pass
        time.sleep(2)
    print("  ERROR: Server did not start", file=sys.stderr)
    return False


def launch_idasql(blob_num, port):
    """Launch idasql in HTTP server mode for a blob."""
    meta = BLOB_META[blob_num]
    name = meta["name"]
    idb_path = os.path.join(BASE, "idb", "blobs", f"blob_{blob_num}_{name}",
                            f"blob_{blob_num}_{name}.dll.pe.i64")
    if not os.path.exists(idb_path):
        print(f"  ERROR: IDB not found: {idb_path}", file=sys.stderr)
        return None

    cmd = [IDASQL, "-s", idb_path, "--http", str(port)]
    print(f"  Launching: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_for_server(port):
        proc.kill()
        return None
    return proc


def load_encrypted_strings(blob_num):
    """Load encrypted strings for a blob."""
    path = os.path.join(BASE, "idb", "blobs", "blob_encrypted_strings.json")
    with open(path) as f:
        data = json.load(f)
    return data.get(f"blob_{blob_num}", [])


# -- Phase 1: Rename globals ------------------------------------------

def discover_unnamed_globals(port):
    """Scan all decompiled code for qword_*, byte_*, dword_* references."""
    # Get all functions
    funcs = sql(port, "SELECT address, name FROM funcs ORDER BY address")
    if not funcs or not funcs.get("rows"):
        return set()

    all_globals = set()
    pattern = re.compile(r'\b(qword|byte|dword|word|unk)_([0-9A-Fa-f]+)\b')

    for row in funcs["rows"]:
        addr = row[0]
        decomp = sql(port, f"SELECT decompile({addr})", timeout=120)
        if decomp and decomp.get("rows") and decomp["rows"][0][0]:
            code = decomp["rows"][0][0]
            for m in pattern.finditer(code):
                prefix = m.group(1)
                hex_addr = m.group(2)
                full_name = f"{prefix}_{hex_addr}"
                all_globals.add((f"0x{hex_addr}", full_name, prefix))

    return all_globals


def rename_globals(port, blob_num, enc_strings):
    """Rename all unnamed globals found in decompiled code."""
    print("  Scanning decompiled code for unnamed globals...")
    unnamed = discover_unnamed_globals(port)
    if not unnamed:
        print("  No unnamed globals found")
        return 0

    print(f"  Found {len(unnamed)} unique unnamed global references")

    # Build encrypted string address -> decrypted value map
    enc_map = {}
    for s in enc_strings:
        va = s["va"].upper().replace("0X", "0x")
        enc_map[int(va, 16)] = s["decrypted"]

    # Load analysis doc for dynamic API resolution info
    analysis_path = os.path.join(BASE, "docs", f"blob_{blob_num}_analysis.md")
    dyn_apis = {}
    if os.path.exists(analysis_path):
        with open(analysis_path, encoding="utf-8") as f:
            content = f.read()
        # Parse dynamic API table: | qword_ADDR | `API` | ...
        for m in re.finditer(r'qword_([0-9A-Fa-f]+)\s*\|\s*`?(\w+)`?', content):
            addr = int(m.group(1), 16)
            api = m.group(2)
            dyn_apis[addr] = api

    renamed = 0
    rename_map = {}  # addr_int -> new_name

    for addr_str, full_name, prefix in sorted(unnamed):
        addr_int = int(addr_str, 16)

        # Priority 1: Encrypted string blob
        if addr_int in enc_map:
            dec = enc_map[addr_int]
            safe = re.sub(r'[^a-zA-Z0-9_]', '_', dec)[:40].rstrip('_')
            if safe and safe[0].isdigit():
                safe = "_" + safe
            new_name = f"enc_{safe}"
            rename_map[addr_int] = new_name
            continue

        # Priority 2: Known dynamic API from analysis doc
        if addr_int in dyn_apis:
            api = dyn_apis[addr_int]
            new_name = f"g_pfn{api}"
            rename_map[addr_int] = new_name
            continue

        # Priority 3: Infer from nearby encrypted strings and xref context
        # Check if this is near an encrypted string (within 0x10 bytes -> likely the cached ptr)
        for enc_addr, dec_val in enc_map.items():
            if abs(addr_int - enc_addr) <= 0x10 and addr_int != enc_addr:
                safe = re.sub(r'[^a-zA-Z0-9_]', '_', dec_val)[:30].rstrip('_')
                if prefix == "qword":
                    new_name = f"g_pfn{safe}"
                else:
                    new_name = f"g_{safe}"
                rename_map[addr_int] = new_name
                break

    # For remaining unnamed, try xref-based naming
    for addr_str, full_name, prefix in sorted(unnamed):
        addr_int = int(addr_str, 16)
        if addr_int in rename_map:
            continue

        # Use xrefs to see what writes to this address
        xrefs = sql(port, f"""
            SELECT func_at(from_ea) as writer FROM xrefs
            WHERE to_ea = {addr_int} LIMIT 5
        """)
        writer_funcs = []
        if xrefs and xrefs.get("rows"):
            writer_funcs = [r[0] for r in xrefs["rows"] if r[0]]

        if writer_funcs:
            first_writer = writer_funcs[0]
            if "resolve_import" in first_writer:
                # This is a cached module handle or API pointer
                if "msvcrt" in first_writer:
                    new_name = f"g_hMsvcrt" if prefix == "qword" else f"g_data_{addr_str[2:]}"
                elif "kernel32" in first_writer:
                    new_name = f"g_hKernel32" if prefix == "qword" else f"g_data_{addr_str[2:]}"
                elif "advapi32" in first_writer:
                    new_name = f"g_hAdvapi32" if prefix == "qword" else f"g_data_{addr_str[2:]}"
                else:
                    new_name = f"g_hModule_{addr_str[2:]}"
            elif "peb_resolve" in first_writer or "hash" in first_writer.lower():
                new_name = f"g_pfnResolved_{addr_str[-4:]}"
            elif "set_context" in first_writer:
                new_name = "g_parent_ctx"
            elif "DllMain" in first_writer or "dispatcher" in first_writer:
                new_name = f"g_state_{addr_str[-4:]}"
            elif "cmd1_write_vtable" in first_writer:
                new_name = f"g_vtable_{addr_str[-4:]}"
            else:
                new_name = f"g_{prefix}_{addr_str[-4:]}"
            rename_map[addr_int] = new_name
        else:
            # Fallback: generic but not IDA auto-names
            if prefix == "qword":
                new_name = f"g_ptr_{addr_str[-4:]}"
            elif prefix == "byte":
                new_name = f"g_data_{addr_str[-4:]}"
            elif prefix == "dword":
                new_name = f"g_dw_{addr_str[-4:]}"
            else:
                new_name = f"g_{prefix}_{addr_str[-4:]}"
            rename_map[addr_int] = new_name

    # Deduplicate names
    seen_names = set()
    for addr_int in sorted(rename_map):
        name = rename_map[addr_int]
        if name in seen_names:
            name = f"{name}_{addr_int & 0xFFFF:04X}"
            rename_map[addr_int] = name
        seen_names.add(name)

    # Apply all renames
    for addr_int, new_name in sorted(rename_map.items()):
        r = sql(port, f"SELECT set_name({addr_int}, '{new_name}')")
        if r:
            renamed += 1

    print(f"  Renamed {renamed} globals")
    return renamed


# -- Phase 2: Rename locals ------------------------------------------

def get_func_list(port):
    """Get all functions sorted by address."""
    r = sql(port, "SELECT address, name, size FROM funcs ORDER BY address")
    if not r or not r.get("rows"):
        return []
    return [(int(row[0]), row[1], int(row[2])) for row in r["rows"]]


def rename_locals_for_func(port, func_addr, func_name):
    """Intelligently rename all generic locals in a function."""
    # Get current locals
    lv = sql(port, f"SELECT idx, name, type, is_arg FROM ctree_lvars WHERE func_addr = {func_addr}")
    if not lv or not lv.get("rows"):
        return 0

    # Get decompiled code for context
    decomp = sql(port, f"SELECT decompile({func_addr})")
    if not decomp or not decomp.get("rows") or not decomp["rows"][0][0]:
        return 0
    code = decomp["rows"][0][0]

    renamed = 0
    used_names = set()
    renames = []

    for row in lv["rows"]:
        idx, name, typ, is_arg = int(row[0]), row[1], row[2] or "", int(row[3])

        # Skip already-named vars
        if not re.match(r'^(v\d+|a\d+|result)$', name):
            used_names.add(name)
            continue

        new_name = infer_local_name(name, typ, is_arg, idx, func_name, code)

        if new_name and new_name != name:
            # Deduplicate
            base = new_name
            suffix = 2
            while new_name in used_names:
                new_name = f"{base}{suffix}"
                suffix += 1
            used_names.add(new_name)
            renames.append((idx, name, new_name))

    # Apply renames (batch then refresh)
    for idx, old, new in renames:
        safe = new.replace("'", "").replace('"', '')
        r = sql(port, f"SELECT rename_lvar({func_addr}, {idx}, '{safe}')")
        if r:
            rj = r.get("rows", [[None]])[0][0]
            if rj:
                try:
                    result = json.loads(rj) if isinstance(rj, str) else rj
                    if result.get("applied"):
                        renamed += 1
                    else:
                        pass  # Name didn't stick, that's ok
                except:
                    renamed += 1  # Assume success if we can't parse
            else:
                renamed += 1

    if renamed > 0:
        sql(port, f"SELECT decompile({func_addr}, 1)")

    return renamed


def infer_local_name(name, typ, is_arg, idx, func_name, code):
    """Infer a descriptive name for a local variable from context."""

    # -- Arguments --
    if is_arg:
        return infer_arg_name(name, typ, idx, func_name, code)

    # -- Result variable --
    if name == "result":
        return "status"

    # -- Scan code for assignment context --
    # Pattern: "name = SomeAPICall("
    assignment_pat = re.compile(rf'\b{re.escape(name)}\b\s*=\s*(\w+)\s*\(')
    assignments = assignment_pat.findall(code)

    if assignments:
        api = assignments[0]
        api_name_map = {
            "GetLastError": "last_error",
            "GetTickCount": "tick_count",
            "OpenProcess": "proc_handle",
            "OpenProcessToken": "token_handle",
            "DuplicateTokenEx": "dup_token",
            "CreateToolhelp32Snapshot": "snapshot",
            "CreateThread": "thread_handle",
            "CreateFileW": "file_handle",
            "CreateFile": "file_handle",
            "GetProcAddress": "proc_addr",
            "GetModuleHandleA": "module_handle",
            "GetModuleHandleW": "module_handle",
            "heap_alloc": "alloc_buf",
            "malloc": "alloc_buf",
            "HeapAlloc": "heap_buf",
            "CreateMutexA": "mutex_handle",
            "CreateMutexW": "mutex_handle",
            "OpenMutexW": "mutex_handle",
            "CreateEventW": "event_handle",
            "CreateEventA": "event_handle",
            "WaitForSingleObject": "wait_result",
            "WaitForMultipleObjects": "wait_result",
            "RegOpenKeyExW": "reg_status",
            "RegCreateKeyExW": "reg_status",
            "RegQueryValueExW": "reg_status",
            "RegSetValueExW": "reg_status",
            "RegEnumValueW": "enum_status",
            "ReadFile": "read_ok",
            "WriteFile": "write_ok",
            "CreateDirectoryW": "dir_ok",
            "DeleteFileW": "del_ok",
            "ExpandEnvironmentStringsW": "expanded_len",
            "InternetOpenA": "inet_handle",
            "InternetConnectA": "connect_handle",
            "HttpOpenRequestA": "request_handle",
            "HttpSendRequestExA": "send_ok",
            "InternetReadFile": "read_ok",
            "Process32FirstW": "found_proc",
            "Process32NextW": "found_next",
            "LookupPrivilegeValueA": "priv_ok",
            "AdjustTokenPrivileges": "adjust_ok",
            "CreateProcessW": "create_ok",
            "CreateProcessAsUserW": "create_ok",
            "ImpersonateLoggedOnUser": "impersonate_ok",
            "RevertToSelf": "revert_ok",
            "CreateEnvironmentBlock": "env_ok",
            "decrypt_string": "dec_str",
            "wide_to_ansi": "ansi_str",
            "utf8_to_wide": "wide_str",
            "wstr_copy": "str_copy",
            "wstr_concat": "str_concat",
            "wstr_init_empty": "empty_str",
            "sbstr_from_utf8": "utf8_str",
            "peb_resolve_api_hash": "resolved_api",
            "htonl": "net_val",
            "ntohl": "host_val",
            "htons": "net_port",
            "ntohs": "host_port",
            "socket": "sock_fd",
            "connect": "conn_result",
            "send": "bytes_sent",
            "recv": "bytes_recvd",
            "select": "select_result",
            "bind": "bind_result",
            "listen": "listen_result",
            "accept": "client_sock",
            "closesocket": "close_result",
            "WSAStartup": "wsa_result",
            "gethostbyname": "host_entry",
            "inet_addr": "ip_addr",
            "atoi": "int_val",
            "lstrlenA": "str_len",
            "lstrlenW": "wstr_len",
            "lstrcpyW": "copy_result",
            "lstrcpyA": "copy_result",
            "lstrcatW": "cat_result",
            "lstrcatA": "cat_result",
            "memset": "memset_result",
            "memcpy": "memcpy_result",
            "memcmp": "cmp_result",
            "GetComputerNameW": "got_name",
            "GetComputerNameA": "got_name",
            "GetUserNameW": "got_user",
            "GetVersionExW": "got_ver",
            "GetNativeSystemInfo": "got_sysinfo",
            "GlobalMemoryStatusEx": "got_mem",
            "GetDiskFreeSpaceExA": "got_disk",
            "EnumDisplaySettingsW": "got_display",
            "GetSystemDefaultLCID": "lcid",
            "GetCurrentProcessId": "cur_pid",
            "GetCurrentThreadId": "cur_tid",
            "GetSystemTime": "sys_time_ok",
            "QueryPerformanceCounter": "qpc_ok",
            "QueryPerformanceFrequency": "qpf_ok",
            "GetFileVersionInfoW": "ver_ok",
            "VerQueryValueW": "ver_query_ok",
            "GetSystemDirectoryW": "sysdir_len",
            "GetVolumeInformationW": "vol_ok",
            "GetSystemMetrics": "metric_val",
            "GetAdaptersAddresses": "adapter_err",
            "DnsQuery_A": "dns_status",
            "DnsRecordListFree": "dns_free_ok",
            "ObtainUserAgentString": "ua_result",
            "InternetSetOptionA": "opt_ok",
            "InternetSetOptionW": "opt_ok",
            "HttpQueryInfoA": "query_ok",
            "HttpEndRequestA": "end_ok",
            "HttpAddRequestHeadersA": "hdr_ok",
            "HttpAddRequestHeadersW": "hdr_ok",
            "InternetCrackUrlA": "crack_ok",
            "SetErrorMode": "old_err_mode",
            "OutputDebugStringA": "dbg_out",
            "CoInitialize": "com_hr",
            "FtpOpenFileA": "ftp_handle",
            "LoadLibraryA": "lib_handle",
            "SetEvent": "set_ok",
            "ResetEvent": "reset_ok",
            "EnterCriticalSection": "cs_enter",
            "LeaveCriticalSection": "cs_leave",
            "InitializeCriticalSection": "cs_init",
            "DeleteCriticalSection": "cs_del",
            "InternetCloseHandle": "inet_close",
            "Sleep": "sleep_ok",
            "CloseHandle": "close_ok",
            "TerminateProcess": "term_ok",
            "ExitProcess": "exit_ok",
            "EnableWindow": "enable_ok",
            "GetClassNameA": "class_len",
            "GetForegroundWindow": "fg_wnd",
            "EnumChildWindows": "enum_ok",
            "wsprintfA": "sprintf_len",
            "SetUnhandledExceptionFilter": "old_filter",
            "RegCloseKey": "reg_close",
            "RegDeleteValueW": "del_status",
            "RegNotifyChangeKeyValue": "notify_status",
            "FindWindowA": "found_wnd",
        }

        if api in api_name_map:
            return api_name_map[api]

        # If it's a g_pfn* call, extract the API name
        if api.startswith("g_pfn"):
            short = api[5:][:20]
            return f"{short.lower()}_result"

        # If it's an internal function call, derive from function name
        if any(api.startswith(p) for p in ["resolve_import", "framework_", "subcmd_",
                                            "vtfn_", "antidebug_", "antitool_",
                                            "checksum_", "antitamper_", "find_process"]):
            return f"{api[:20]}_ret"

    # -- Type-based inference --
    typ_lower = typ.lower()
    if "PROCESSENTRY32" in typ or "tagPROCESSENTRY32" in typ:
        return "proc_entry"
    if "STARTUPINFO" in typ:
        return "startup_info"
    if "PROCESS_INFORMATION" in typ:
        return "proc_info"
    if "SECURITY_ATTRIBUTES" in typ:
        return "sec_attr"
    if "TOKEN_PRIVILEGES" in typ:
        return "token_priv"
    if "LUID" in typ:
        return "priv_luid"
    if "OSVERSIONINFO" in typ:
        return "os_ver"
    if "MEMORYSTATUSEX" in typ:
        return "mem_stat"
    if "SYSTEM_INFO" in typ:
        return "sys_info"
    if "DEVMODE" in typ:
        return "dev_mode"
    if "LARGE_INTEGER" in typ:
        return "perf_counter"
    if "CRITICAL_SECTION" in typ:
        return "crit_sec"
    if "sockaddr_in" in typ:
        return "sock_addr"
    if "sockaddr" in typ:
        return "addr_info"
    if "hostent" in typ:
        return "host_ent"
    if "fd_set" in typ:
        return "fd_set"
    if "timeval" in typ:
        return "timeout_val"
    if "WSADATA" in typ:
        return "wsa_data"
    if "INTERNET_BUFFERS" in typ:
        return "inet_buf"
    if "URL_COMPONENTS" in typ:
        return "url_parts"
    if "HKEY" in typ:
        return "reg_key"
    if "HANDLE" in typ:
        return "handle"
    if "HMODULE" in typ:
        return "module"
    if "HINTERNET" in typ:
        return "inet_handle"
    if "SOCKET" in typ or ("unsigned int" in typ_lower and "sock" in code.lower()):
        return "sock"

    # Pointer-to-known-types
    if "wchar" in typ_lower or "WCHAR" in typ:
        return "wide_buf"
    if "BOOL" in typ:
        return "success"
    if "DWORD" in typ:
        # Try to figure out what DWORD it is from context
        if f"{name} = " in code and "GetLastError" in code:
            return "error_code"
        if f"&{name}" in code and "cbSize" in code:
            return "cb_size"
        return "dw_val"
    if "size_t" in typ or ("unsigned" in typ_lower and "int64" in typ_lower):
        return "buf_size"

    # -- Pointer variables --
    if "*" in typ:
        if "char *" in typ or "CHAR *" in typ:
            return "str_ptr"
        if "BYTE *" in typ or "unsigned __int8 *" in typ:
            return "byte_ptr"
        if "void *" in typ:
            return "data_ptr"
        return "ptr"

    # -- Address-of patterns (variable used as &name) --
    if f"&{name}" in code:
        if "Process32" in code:
            return "proc_entry"
        if "token" in code.lower():
            return "token"
        return "out_param"

    # -- Generic type-based fallback --
    if "int" in typ_lower or "__int64" in typ_lower:
        # Count-like usage
        if re.search(rf'for\s*\([^;]*{re.escape(name)}\s*=\s*0', code):
            return "idx"
        if re.search(rf'{re.escape(name)}\s*<\s*\d', code):
            return "counter"
        if re.search(rf'{re.escape(name)}\s*\+\+', code):
            return "iter"
        return "ret_val"

    # Absolute fallback
    num = re.search(r'\d+', name)
    n = num.group() if num else str(idx)
    return f"local_{n}"


def infer_arg_name(name, typ, idx, func_name, code):
    """Infer argument name based on function semantics."""
    fn = func_name.lower()

    # DllMain pattern
    if "dllmain" in fn or "dispatcher" in fn:
        arg_names = ["hinstDLL", "fdwReason", "lpvReserved"]
        if idx < len(arg_names):
            return arg_names[idx]

    # Vtable/subcommand functions: first arg is context
    if fn.startswith("vtfn_") or fn.startswith("subcmd_") or fn.startswith("cmd_"):
        if idx == 0:
            return "ctx"
        if idx == 1:
            return "cmd_buf"
        if idx == 2:
            return "cmd_size"
        return f"arg{idx}"

    # Common function patterns
    patterns = {
        "resolve_import": ["enc_dll_name", "enc_api_name", "out_pfn"],
        "decrypt_string": ["out_str", "enc_blob"],
        "find_process": ["target_name"],
        "process_launcher": ["cmd_line", "target_pid"],
        "create_process": ["cmd_line", "flags"],
        "enable_privilege": ["privilege_name"],
        "checksum_memory": ["data", "length"],
        "heap_alloc": ["size"],
        "heap_free": ["ptr"],
        "sbstr_free": ["str_obj"],
        "sbstr_from_utf8": ["out_str", "utf8_src"],
        "wstr_copy": ["dst", "src"],
        "wstr_concat": ["dst", "src"],
        "wstr_init_empty": ["str_obj"],
        "utf8_to_wide": ["utf8_str"],
        "wide_to_ansi": ["wide_str"],
        "open_and_terminate": ["pid"],
        "antitool_open_device": ["device_path"],
        "set_context_ptr": ["parent_ctx"],
        "framework_read_config": ["ctx", "out_buf", "out_size"],
        "framework_decode_commands": ["ctx", "buf", "size"],
        "framework_send_response": ["ctx", "buf", "size"],
        "framework_wait_cmd": ["ctx", "timeout_ms"],
        "install_service_entry": ["ctx"],
        "get_vtable_ptr": ["out_vtable"],
        "get_plugin_id": ["out_id"],
        "decrypt_and_set_name": ["ctx", "out_name"],
        "cmd1_write_vtable": ["vtable_ptr"],
        "try_launch_commands": ["ctx"],
        "antidebug_detect_tools": ["hwnd", "lparam"],
    }

    for pattern, arg_names in patterns.items():
        if pattern in fn:
            if idx < len(arg_names):
                return arg_names[idx]
            return f"arg{idx}"

    # Type-based argument naming
    if typ:
        if "HWND" in typ:
            return "hwnd"
        if "HINSTANCE" in typ or "HMODULE" in typ:
            return "hModule"
        if "LPARAM" in typ:
            return "lParam"
        if "WPARAM" in typ:
            return "wParam"
        if "wchar" in typ.lower() or "WCHAR" in typ:
            return f"wsz_arg{idx}"
        if "char *" in typ:
            return f"sz_arg{idx}"
        if "HANDLE" in typ:
            return f"handle_arg{idx}"
        if "DWORD" in typ:
            return f"dw_arg{idx}"
        if "*" in typ and idx == 0:
            return "this_ptr"
        if "*" in typ:
            return f"ptr_arg{idx}"

    # Generic
    if idx == 0:
        return "this_ptr"
    return f"param{idx}"


# -- Phase 3: Decompile and assemble --------------------------------

def decompile_all(port):
    """Decompile all functions, return dict addr -> {name, size, code}."""
    funcs = sql(port, "SELECT address, name, size FROM funcs ORDER BY address")
    if not funcs or not funcs.get("rows"):
        return {}

    results = {}
    for row in funcs["rows"]:
        addr, name, size = int(row[0]), row[1], int(row[2])
        decomp = sql(port, f"SELECT decompile({addr}, 1)", timeout=120)
        if decomp and decomp.get("rows") and decomp["rows"][0][0]:
            results[addr] = {"name": name, "size": size, "code": decomp["rows"][0][0]}
        else:
            print(f"  WARN: Failed to decompile {name} @ 0x{addr:X}")
    return results


def strip_ida_artifacts(code):
    """Remove IDA-specific artifacts from decompiled code."""
    lines = code.split("\n")
    cleaned = []
    for line in lines:
        # Remove /* ADDR */ prefixes (with or without address)
        line = re.sub(r'^/\*\s*[0-9A-Fa-f]*\s*\*/\s?', '', line)
        # Remove [lv:N] hints
        line = re.sub(r'\s*\[lv:\d+\]', '', line)
        cleaned.append(line)
    return "\n".join(cleaned)


def assemble_c_file(blob_num, functions, enc_strings):
    """Assemble clean .c file from decompiled functions."""
    meta = BLOB_META[blob_num]
    name = meta["name"]

    lines = []
    lines.append(f"/*")
    lines.append(f" * blob_{blob_num}_{name}.c -- ScatterBrain Plugin: {name}")
    lines.append(f" *")
    lines.append(f" * Role: {meta['role']}")
    lines.append(f" * Functions: {len(functions)}")
    lines.append(f" * Compiled: 2017-02-23 (timestamp ~0x58AEBA)")
    lines.append(f" *")
    lines.append(f" * Recovered from IDA decompilation via idasql.")
    lines.append(f" * Part of the ScatterBrain/PoisonPlug malware analysis project.")
    lines.append(f" */")
    lines.append("")
    lines.append('#include "sb_types.h"')
    lines.append("")

    # Encrypted strings reference
    if enc_strings:
        lines.append("/* --------------------------------------------------------------")
        lines.append(" * Encrypted Strings (polynomial XOR cipher)")
        lines.append(" * -------------------------------------------------------------- */")
        for s in enc_strings:
            lines.append(f"// {s['va']}: \"{s['decrypted']}\"")
        lines.append("")

    # Function implementations
    lines.append("/* --------------------------------------------------------------")
    lines.append(" * Function Implementations")
    lines.append(" * -------------------------------------------------------------- */")
    lines.append("")

    for addr in sorted(functions.keys()):
        f = functions[addr]
        clean_code = strip_ida_artifacts(f["code"])
        lines.append(f"/* -- {f['name']} (0x{addr:X}, {f['size']} bytes) {'-' * max(1, 50 - len(f['name']))} */")
        lines.append("")
        lines.append(clean_code)
        lines.append("")

    return "\n".join(lines)


def postprocess_generic_names(content, enc_strings):
    """Replace any remaining byte_*/qword_*/dword_* with descriptive names."""
    enc_name_map = {}
    for s in enc_strings:
        addr_hex = s["va"].replace("0x", "").replace("0X", "").upper()
        dec = s["decrypted"]
        safe = re.sub(r'[^a-zA-Z0-9_]', '_', dec)[:40].rstrip('_')
        if safe and safe[0].isdigit():
            safe = "_" + safe
        enc_name_map[addr_hex] = f"enc_{safe}"

    def replace_match(m):
        prefix = m.group(1)
        addr = m.group(2).upper()
        if addr in enc_name_map:
            return enc_name_map[addr]
        return f"g_{prefix}_{addr[-4:]}"

    content = re.sub(r'\b(byte|qword|dword|word)_([0-9A-Fa-f]+)\b', replace_match, content)
    return content


# -- Main pipeline ---------------------------------------------------

def process_blob(blob_num, port=None, skip_launch=False):
    """Process a single blob end-to-end."""
    meta = BLOB_META[blob_num]
    name = meta["name"]
    if port is None:
        port = meta["port"]

    print(f"\n{'='*60}")
    print(f"  blob_{blob_num} ({name}) -- port {port}")
    print(f"{'='*60}")

    # Launch
    proc = None
    if not skip_launch:
        proc = launch_idasql(blob_num, port)
        if proc is None:
            return False
    else:
        if not wait_for_server(port, max_wait=5):
            proc = launch_idasql(blob_num, port)
            if proc is None:
                return False

    try:
        enc_strings = load_encrypted_strings(blob_num)
        print(f"  {len(enc_strings)} encrypted strings loaded")

        # Phase 1: Rename globals
        print("\n  -- Phase 1: Rename globals --")
        rename_globals(port, blob_num, enc_strings)

        # Phase 2: Rename locals
        print("\n  -- Phase 2: Rename locals --")
        func_list = get_func_list(port)
        print(f"  {len(func_list)} functions to process")
        total_local_renames = 0
        for func_addr, func_name, func_size in func_list:
            n = rename_locals_for_func(port, func_addr, func_name)
            if n > 0:
                total_local_renames += n
                print(f"    {func_name}: {n} locals renamed")
        print(f"  Total locals renamed: {total_local_renames}")

        # Phase 3: Final decompile + assemble
        print("\n  -- Phase 3: Decompile + assemble --")
        functions = decompile_all(port)
        print(f"  Decompiled {len(functions)} functions")

        output_dir = os.path.join(BASE, "src", "blobs")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"blob_{blob_num}_{name}.c")
        content = assemble_c_file(blob_num, functions, enc_strings)

        # Post-process: replace any remaining byte_*/qword_*/dword_* with names
        content = postprocess_generic_names(content, enc_strings)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  Wrote: {output_path} ({len(content):,} bytes)")

        # Verify
        g_count = len(re.findall(r'\b(qword|byte|dword|word)_[0-9A-Fa-f]+\b', content))
        v_count = len(re.findall(r'\bv\d+\b', content))
        a_count = len(re.findall(r'\ba[1-9]\d*\b', content))
        print(f"  Remaining: {g_count} generic globals, {v_count} v-locals, {a_count} a-params")

        # Save
        print("\n  -- Save + shutdown --")
        sql(port, "SELECT save_database()")
        print("  IDB saved")
        return True

    finally:
        try:
            requests.post(f"http://127.0.0.1:{port}/shutdown", timeout=10)
        except:
            pass
        if proc:
            try:
                proc.wait(timeout=30)
            except:
                proc.kill()
        print(f"  Done: blob_{blob_num}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--blob", type=int, required=True)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--skip-launch", action="store_true")
    args = parser.parse_args()

    if args.blob == -1:
        for i in range(8):
            ok = process_blob(i, args.port, args.skip_launch)
            if not ok:
                print(f"  FAILED: blob_{i}", file=sys.stderr)
    else:
        if args.blob not in BLOB_META:
            print(f"Invalid blob: {args.blob}", file=sys.stderr)
            sys.exit(1)
        ok = process_blob(args.blob, args.port, args.skip_launch)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
