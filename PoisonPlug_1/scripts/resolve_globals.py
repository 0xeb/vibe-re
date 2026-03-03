#!/usr/bin/env python
"""
resolve_globals.py -- Resolve generic global names by analyzing decompiled pseudocode.

For each blob, decompiles all functions and uses pattern matching to identify:
  - API function pointers (called indirectly)
  - Module handles
  - State variables
  - Vtable entries

Usage:
    python scripts/resolve_globals.py --port PORT [--save]
"""

import argparse
import json
import os
import re
import sys
import requests

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sql(port, query, timeout=120):
    url = f"http://127.0.0.1:{port}/query"
    try:
        r = requests.post(url, data=query, timeout=timeout)
        r.raise_for_status()
        j = r.json()
        ok = j.get("success")
        if ok is None:
            ok = "error" not in j
        if not ok:
            return None
        return j
    except Exception as e:
        return None


def get_all_names(port):
    """Get all named addresses as a dict {addr: name}."""
    r = sql(port, "SELECT address, name FROM names ORDER BY address")
    if not r:
        return {}
    return {int(row[0]): row[1] for row in r.get("rows", [])}


def decompile_func(port, addr):
    """Decompile a function and return the text."""
    r = sql(port, f"SELECT decompile({addr})", timeout=300)
    if r and r.get("rows") and r["rows"][0][0]:
        return r["rows"][0][0]
    return None


def analyze_global_usage(all_code, global_name):
    """Analyze how a global is used across all decompiled code."""
    info = {
        "called_as_func": False,
        "call_arg_patterns": [],
        "assigned_from": [],
        "used_as_arg_to": [],
        "context_hints": [],
    }

    for fname, code in all_code:
        if global_name not in code:
            continue

        for line in code.split("\n"):
            if global_name not in line:
                continue

            # Check if called as function: global_name(...)
            call_match = re.search(rf'\b{re.escape(global_name)}\s*\(([^)]*)\)', line)
            if call_match:
                info["called_as_func"] = True
                args = call_match.group(1).strip()
                info["call_arg_patterns"].append((fname, args))

            # Check if assigned: global_name = expr
            assign_match = re.search(rf'{re.escape(global_name)}\s*=\s*(.+)', line)
            if assign_match:
                rhs = assign_match.group(1).strip().rstrip(";")
                info["assigned_from"].append((fname, rhs))

            # Check if passed as argument to another function
            arg_match = re.search(r'(\w+)\s*\([^)]*' + re.escape(global_name) + r'[^)]*\)', line)
            if arg_match:
                callee = arg_match.group(1)
                if callee != global_name:
                    info["used_as_arg_to"].append((fname, callee))

    return info


# Common API signature patterns for identification
API_PATTERNS = {
    # Registry APIs
    r'RegOpenKeyEx': "RegOpenKeyExW",
    r'RegCloseKey': "RegCloseKey",
    r'RegEnumValue': "RegEnumValueW",
    r'RegQueryValue': "RegQueryValueExW",
    r'RegDeleteValue': "RegDeleteValueW",
    r'RegSetValue': "RegSetValueExW",
    r'RegCreateKeyEx': "RegCreateKeyExW",
    r'RegNotifyChangeKeyValue': "RegNotifyChangeKeyValue",
    # Kernel32 APIs
    r'CreateEvent': "CreateEventW",
    r'GetModuleHandle': "GetModuleHandleA",
    r'SetUnhandledExceptionFilter': "SetUnhandledExceptionFilter",
    r'GetCurrentThread': "GetCurrentThread",
    r'TerminateThread': "TerminateThread",
    r'WaitForSingleObject': "WaitForSingleObject",
    r'CreateThread': "CreateThread",
    r'CloseHandle': "CloseHandle",
    r'Sleep': "Sleep",
    # String APIs
    r'wsprintfA': "wsprintfA",
    r'lstrcpy': "lstrcpyW",
    r'lstrcat': "lstrcatW",
    r'lstrlen': "lstrlenW",
    r'memcpy': "memcpy",
    r'memset': "memset",
    # Network APIs
    r'ntohl': "ntohl",
    r'htonl': "htonl",
    r'htons': "htons",
    r'ntohs': "ntohs",
    r'socket': "socket",
    r'connect': "connect",
    r'send\b': "send",
    r'recv\b': "recv",
    r'closesocket': "closesocket",
    r'WSAStartup': "WSAStartup",
    r'WSACleanup': "WSACleanup",
    r'WSAGetLastError': "WSAGetLastError",
    r'setsockopt': "setsockopt",
    r'bind\b': "bind",
    r'listen': "listen",
    r'accept': "accept",
    r'select': "select",
    r'sendto': "sendto",
    r'recvfrom': "recvfrom",
    r'gethostbyname': "gethostbyname",
    r'ioctlsocket': "ioctlsocket",
    # WinInet APIs
    r'InternetOpen[^C]': "InternetOpenA",
    r'InternetConnect': "InternetConnectA",
    r'HttpOpenRequest': "HttpOpenRequestA",
    r'HttpSendRequest': "HttpSendRequestExA",
    r'HttpEndRequest': "HttpEndRequestA",
    r'InternetReadFile': "InternetReadFile",
    r'InternetCloseHandle': "InternetCloseHandle",
    r'InternetSetOption': "InternetSetOptionA",
    r'HttpAddRequestHeaders': "HttpAddRequestHeadersW",
    r'HttpQueryInfo': "HttpQueryInfoA",
    r'InternetQueryOption': "InternetQueryOptionW",
    # Other
    r'CoInitialize\b': "CoInitialize",
    r'CoUninitialize': "CoUninitialize",
    r'ObtainUserAgentString': "ObtainUserAgentString",
    r'GetFileVersionInfo': "GetFileVersionInfoW",
    r'VerQueryValue': "VerQueryValueW",
    r'OutputDebugString': "OutputDebugStringA",
    r'SetErrorMode': "SetErrorMode",
    r'GetSystemTime': "GetSystemTime",
    r'GlobalMemoryStatusEx': "GlobalMemoryStatusEx",
    r'GetNativeSystemInfo': "GetNativeSystemInfo",
    r'GetDiskFreeSpaceEx': "GetDiskFreeSpaceExA",
    r'GetSystemDefaultLCID': "GetSystemDefaultLCID",
    r'GetCurrentProcessId': "GetCurrentProcessId",
    r'GetVersionEx': "GetVersionExW",
    r'GetComputerName': "GetComputerNameW",
    r'WaitForMultipleObjects': "WaitForMultipleObjects",
    r'EnumDisplaySettings': "EnumDisplaySettingsW",
    r'GetSystemMetrics': "GetSystemMetrics",
    r'LoadLibraryA': "LoadLibraryA",
    r'GetProcAddress': "GetProcAddress",
    r'QueryPerformanceCounter': "QueryPerformanceCounter",
    r'QueryPerformanceFrequency': "QueryPerformanceFrequency",
    r'InitializeCriticalSection': "InitializeCriticalSection",
    r'DeleteCriticalSection': "DeleteCriticalSection",
    r'EnterCriticalSection': "EnterCriticalSection",
    r'LeaveCriticalSection': "LeaveCriticalSection",
    r'ResetEvent': "ResetEvent",
    r'SetEvent': "SetEvent",
    r'GetTickCount': "GetTickCount",
    r'GetCurrentThreadId': "GetCurrentThreadId",
    r'WSAIoctl': "WSAIoctl",
    r'FtpOpenFile': "FtpOpenFileA",
    r'DnsQuery': "DnsQuery_A",
    r'DnsRecordListFree': "DnsRecordListFree",
}


def infer_api_from_decrypt(all_code, global_name):
    """Check if a global is assigned from a decrypt_string + resolve pattern."""
    for fname, code in all_code:
        if global_name not in code:
            continue
        lines = code.split("\n")
        for i, line in enumerate(lines):
            if global_name not in line:
                continue
            # Pattern: g_xxx = resolve_xxx_proc(...)
            # Look at surrounding lines for decrypt_string calls
            context = "\n".join(lines[max(0, i-5):i+5])

            # Check for enc_ references in context
            enc_matches = re.findall(r'\benc_(\w+)', context)
            for enc in enc_matches:
                # Map encrypted string name to API
                for pattern, api_name in API_PATTERNS.items():
                    clean_api = api_name.replace("W", "").replace("A", "").replace("Ex", "")
                    if enc.lower().replace("_", "") == clean_api.lower().replace("_", ""):
                        return api_name
                    if enc.lower() in api_name.lower() or api_name.lower() in enc.lower():
                        return api_name
                # Direct match
                if enc in API_PATTERNS.values():
                    return enc

    return None


def infer_api_from_call_args(info, all_code, global_name):
    """Infer API name from how it's called (argument count and types)."""
    if not info["called_as_func"]:
        return None

    for fname, args in info["call_arg_patterns"]:
        # Count arguments
        if not args:
            arg_count = 0
        else:
            arg_count = len([a.strip() for a in args.split(",") if a.strip()])

        # Look for distinctive argument patterns
        arg_text = args.lower()

        # Registry patterns
        if "hkey" in arg_text or "reg" in arg_text.replace("region", ""):
            if arg_count >= 6:
                return "RegEnumValueW"
            if arg_count >= 5:
                return "RegQueryValueExW" if "query" in fname.lower() else "RegSetValueExW"
            if arg_count == 2:
                return "RegCloseKey"

        # Event patterns
        if "event" in fname.lower() or "event" in arg_text:
            if arg_count <= 1:
                return "ResetEvent"

        # Thread patterns
        if "thread" in fname.lower() and arg_count >= 3:
            return "CreateThread"

    return None


def resolve_globals(port, save=False):
    """Main resolution logic."""
    names = get_all_names(port)

    # Get function list
    r = sql(port, "SELECT address, name FROM funcs ORDER BY address")
    if not r:
        print("ERROR: Cannot get functions", file=sys.stderr)
        return

    funcs = [(int(row[0]), row[1]) for row in r.get("rows", [])]
    print(f"  {len(funcs)} functions to analyze")

    # Decompile all functions
    print("  Decompiling all functions...")
    all_code = []
    for addr, name in funcs:
        code = decompile_func(port, addr)
        if code:
            all_code.append((name, code))
    print(f"  Decompiled {len(all_code)} functions")

    # Find all globals that need resolution
    to_resolve = {}
    for addr, name in names.items():
        if re.match(r'^g_(qword|byte|dword|word|unk|pfn_0x|data_0x|state_)', name):
            to_resolve[addr] = name

    print(f"  {len(to_resolve)} globals to resolve")

    # Analyze each global
    resolved = {}
    for addr, name in sorted(to_resolve.items()):
        info = analyze_global_usage(all_code, name)

        new_name = None

        # Try decrypt pattern first
        api = infer_api_from_decrypt(all_code, name)
        if api:
            new_name = f"g_pfn{api}"
        elif info["called_as_func"]:
            # It's called as a function — try to identify by call context
            api = infer_api_from_call_args(info, all_code, name)
            if api:
                new_name = f"g_pfn{api}"
            else:
                # Check assigned_from for resolve_* patterns
                for fname, rhs in info["assigned_from"]:
                    if "resolve" in rhs:
                        # Extract the encrypted string reference from context
                        api = infer_api_from_decrypt(all_code, name)
                        if api:
                            new_name = f"g_pfn{api}"
                            break

        if new_name is None:
            # Check if it's a vtable entry (stores function pointer to a named function)
            for fname, rhs in info.get("assigned_from", []):
                for func_addr, func_name in funcs:
                    if func_name in rhs and func_name != name:
                        new_name = f"g_vtfn_{func_name}"
                        break
                if new_name:
                    break

        if new_name is None:
            # Check for parent context pattern
            for fname, rhs in info.get("assigned_from", []):
                if "lpReserved" in rhs or "param" in rhs.lower():
                    if "state" in name and info.get("used_as_arg_to"):
                        for uf, callee in info["used_as_arg_to"]:
                            if "resolve" in callee.lower() or "callback" in callee.lower():
                                new_name = "g_pParentCtx"
                                break

        if new_name:
            resolved[addr] = (name, new_name)
            print(f"  0x{addr:X}: {name} -> {new_name}")

    # Apply renames
    if resolved:
        used_names = set(names.values())
        for addr, (old_name, new_name) in sorted(resolved.items()):
            # Handle duplicates
            base = new_name
            suffix = 2
            while new_name in used_names:
                new_name = f"{base}_{suffix}"
                suffix += 1
            used_names.add(new_name)

            safe = new_name.replace("'", "''")
            sql(port, f"SELECT set_name({addr}, '{safe}')")

        print(f"\n  Resolved {len(resolved)} globals")

        if save:
            sql(port, "SELECT save_database()")
            print("  IDB saved")

    # Report remaining
    r = sql(port, "SELECT count(*) FROM names WHERE name LIKE 'g_qword_%' OR name LIKE 'g_pfn_0x%' OR name LIKE 'g_data_0x%' OR name LIKE 'g_state_%'")
    if r and r.get("rows"):
        remaining = int(r["rows"][0][0])
        print(f"  Remaining generic globals: {remaining}")

    return resolved


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args()

    resolve_globals(args.port, save=args.save)


if __name__ == "__main__":
    main()
