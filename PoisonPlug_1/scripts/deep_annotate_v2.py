#!/usr/bin/env python
"""
deep_annotate_v2.py -- Full deep annotation pipeline for a single blob IDB.

Pipeline:
  1. Create api_hash_t enum + apply to PEB hash resolve functions
  2. Name encrypted string globals (enc_*)
  3. Initial pass: name function pointers and data globals
  4. Decompile all functions and analyze global usage patterns
  5. Resolve remaining generics by context analysis
  6. Clean up vtable/state names
  7. Save IDB + generate clean .c file

Usage:
    python scripts/deep_annotate_v2.py --blob N [--port PORT] [--launch] [--shutdown]
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import requests

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDASQL = os.environ.get("IDASQL_PATH", "idasql")

BLOB_META = {
    0: {"name": "Install"}, 1: {"name": "Plugins"}, 2: {"name": "Config"},
    3: {"name": "Online"}, 4: {"name": "TCP"}, 5: {"name": "HTTP"},
    6: {"name": "UDP"}, 7: {"name": "DNS"},
}

WS2_32_ORDINALS = {
    1: "accept", 2: "bind", 3: "closesocket", 4: "connect",
    5: "getpeername", 6: "getsockname", 7: "getsockopt",
    8: "htonl", 9: "htons", 10: "ioctlsocket", 11: "inet_addr",
    12: "inet_ntoa", 13: "listen", 14: "ntohl", 15: "ntohs",
    16: "recv", 17: "recvfrom", 18: "select", 19: "send",
    20: "sendto", 21: "setsockopt", 22: "shutdown", 23: "socket",
    51: "gethostbyaddr", 52: "gethostbyname",
    111: "WSAGetLastError", 115: "WSAStartup", 116: "WSACleanup",
}


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
    except:
        return None


def wait_for_server(port, max_wait=120):
    start = time.time()
    while time.time() - start < max_wait:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/status", timeout=3)
            if r.status_code == 200:
                return True
        except:
            pass
        time.sleep(2)
    return False


def launch_server(blob_num, port, name):
    idb = os.path.join(BASE, "idb", "blobs", f"blob_{blob_num}_{name}",
                       f"blob_{blob_num}_{name}.dll.pe.i64")
    if not os.path.exists(idb):
        print(f"  ERROR: IDB not found: {idb}", file=sys.stderr)
        return None
    cmd = [IDASQL, "-s", idb, "--http", str(port)]
    print(f"  Launching: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_for_server(port):
        proc.kill()
        print(f"  ERROR: Server failed to start", file=sys.stderr)
        return None
    print(f"  Server ready on port {port}")
    return proc


def set_name_safe(port, addr, name):
    """Set name, handling duplicates by appending suffix."""
    safe = name.replace("'", "''")
    r = sql(port, f"SELECT set_name({addr}, '{safe}')")
    if r is None:
        for i in range(2, 20):
            r = sql(port, f"SELECT set_name({addr}, '{safe}_{i}')")
            if r:
                return f"{name}_{i}"
    return name


def load_encrypted_strings(blob_num):
    path = os.path.join(BASE, "idb", "blobs", "blob_encrypted_strings.json")
    with open(path) as f:
        data = json.load(f)
    return data.get(f"blob_{blob_num}", [])


def load_imports(blob_num):
    path = os.path.join(BASE, "idb", "blobs", "blob_pe_summary.json")
    with open(path) as f:
        data = json.load(f)
    imports = []
    for dll_entry in data[blob_num].get("imports", []):
        dll = dll_entry["dll"]
        for func in dll_entry["functions"]:
            if func.startswith("ord#"):
                ordinal = int(func[4:])
                resolved = WS2_32_ORDINALS.get(ordinal, func)
                imports.append((dll, resolved))
            else:
                imports.append((dll, func))
    return imports


# ---- Step 1: Hash Enum ----

def step_hash_enum(port):
    """Create api_hash_t enum and apply to hash resolve functions."""
    print("\n--- Step 1: Hash enum ---")
    decl = (
        "typedef enum { "
        "HASH_NONE = 0, "
        "HASH_LoadLibraryA = 0xBDA26FE6, "
        "HASH_GetProcAddress = 0xA16DC157, "
        "HASH_VirtualAlloc = 0x24A6650A, "
        "HASH_Sleep = 0x27BE7673, "
        "HASH_LocalAlloc = 0x95D9FE52, "
        "HASH_WideCharToMultiByte = 0x991AB7EE, "
        "HASH_MultiByteToWideChar = 0xB8D629F8, "
        "HASH_LocalFree = 0xF339F5E3 "
        "} api_hash_t;"
    )
    sql(port, f"SELECT parse_decls('{decl}')")

    # Find and retype hash resolve functions
    r = sql(port, "SELECT address, name FROM funcs WHERE name LIKE '%hash_resolve%' OR name LIKE '%peb_resolve%'")
    if r and r.get("rows"):
        for row in r["rows"]:
            addr = int(row[0])
            name = row[1]
            proto = f"void * __fastcall {name}(api_hash_t hash);"
            sql(port, f"UPDATE funcs SET prototype = '{proto}' WHERE address = {addr}")
            print(f"  Applied api_hash_t to {name}")


# ---- Step 2: Encrypted Strings ----

def step_encrypted_strings(port, enc_strings):
    """Name encrypted string byte_* globals."""
    print("\n--- Step 2: Encrypted string globals ---")
    named = 0
    used = set()
    for s in enc_strings:
        va = int(s["va"], 16)
        dec = s["decrypted"]
        clean = re.sub(r'[^a-zA-Z0-9_]', '_', dec)[:40]
        enc_name = f"enc_{clean}"

        # Ensure uniqueness
        base = enc_name
        suffix = 2
        while enc_name in used:
            enc_name = f"{base}_{suffix}"
            suffix += 1
        used.add(enc_name)

        # Check if already properly named
        r = sql(port, f"SELECT name FROM names WHERE address = {va}")
        if r and r.get("rows"):
            existing = r["rows"][0][0]
            if existing and existing.startswith("enc_"):
                continue

        set_name_safe(port, va, enc_name)
        named += 1
    print(f"  Named {named} encrypted strings")


# ---- Step 3: Decompile + Analyze ----

def decompile_all(port):
    """Decompile all functions, return list of (addr, name, size, code)."""
    r = sql(port, "SELECT address, name, size FROM funcs ORDER BY address")
    if not r:
        return []
    results = []
    for row in r.get("rows", []):
        addr, name, size = int(row[0]), row[1], int(row[2]) if row[2] else 0
        d = sql(port, f"SELECT decompile({addr})", timeout=300)
        code = d["rows"][0][0] if d and d.get("rows") and d["rows"][0][0] else ""
        results.append((addr, name, size, code))
    return results


def analyze_global_in_code(global_name, all_code):
    """Analyze how a global is used across all decompiled functions."""
    info = {"called": False, "call_lines": [], "assign_lines": [], "ref_funcs": []}
    for fname, code in all_code:
        if global_name not in code:
            continue
        info["ref_funcs"].append(fname)
        for line in code.split("\n"):
            if global_name not in line:
                continue
            # Called as function?
            if re.search(rf'\b{re.escape(global_name)}\s*\(', line):
                info["called"] = True
                info["call_lines"].append((fname, line.strip()))
            # Assigned?
            if re.search(rf'{re.escape(global_name)}\s*=', line):
                info["assign_lines"].append((fname, line.strip()))
    return info


def infer_api_from_call(info):
    """Try to identify an API from call argument patterns."""
    for fname, line in info.get("call_lines", []):
        # Count args
        m = re.search(r'\(([^)]*)\)', line)
        if not m:
            continue
        args = m.group(1)
        arg_count = len([a for a in args.split(",") if a.strip()]) if args.strip() else 0

        line_lower = line.lower()

        # Check for specific patterns
        if "0xfffffffe" in line or "0xFFFFFFFE" in line:
            return "GetCurrentProcess"
        if "0xffffffff" in line and arg_count == 2:
            return "WaitForSingleObject"
        if "unhandled" in fname or "exception" in fname:
            if arg_count == 0:
                return "GetCurrentThread"
            if arg_count == 2:
                return "TerminateThread"
        if arg_count >= 8 and ("enum" in fname.lower() or "reg_enum" in fname.lower()):
            return "RegEnumValueW"
        if arg_count >= 5 and ("open" in fname.lower() or "reg_open" in fname.lower()):
            return "RegOpenKeyExW"
        if arg_count == 6 and "query" in fname.lower():
            return "RegQueryValueExW"
        if arg_count >= 5 and "set" in fname.lower() and "reg" in fname.lower():
            return "RegSetValueExW"
        if arg_count == 2 and "delete" in fname.lower():
            return "RegDeleteValueW"
        if arg_count == 1 and ("close" in line_lower or "close" in fname.lower()):
            return "RegCloseKey"
        if arg_count == 6 and "notify" in fname.lower():
            return "RegNotifyChangeKeyValue"
        if arg_count >= 3 and arg_count <= 4 and ("event" in fname.lower() or "event" in line_lower):
            return "CreateEventW"

        # WinInet patterns
        if "internet" in line_lower and arg_count >= 4:
            if "open" in fname.lower():
                return "InternetOpenA"
        if "http" in line_lower and "open" in line_lower:
            return "HttpOpenRequestA"

    return None


def infer_from_enc_context(global_name, all_code, enc_map):
    """Check if global is assigned near an encrypted string reference (API resolve pattern)."""
    for fname, code in all_code:
        if global_name not in code:
            continue
        lines = code.split("\n")
        for i, line in enumerate(lines):
            if global_name not in line or "=" not in line:
                continue
            # Look at context window
            context = "\n".join(lines[max(0, i-8):i+3])
            for enc_va, api_name in enc_map.items():
                if f"enc_{api_name}" in context:
                    return api_name
    return None


def step_resolve_globals(port, enc_strings, all_code):
    """Resolve all remaining generic global names using decompilation analysis."""
    print("\n--- Step 3: Resolve generic globals ---")

    # Build enc_va -> clean_name map
    enc_map = {}
    for s in enc_strings:
        va = int(s["va"], 16)
        clean = re.sub(r'[^a-zA-Z0-9_]', '_', s["decrypted"])[:40]
        enc_map[va] = clean

    # Get all generically-named globals
    r = sql(port, (
        "SELECT address, name FROM names WHERE "
        "name LIKE 'g_qword_%' OR name LIKE 'g_byte_%' OR name LIKE 'g_dword_%' "
        "OR name LIKE 'g_pfn_0x%' OR name LIKE 'g_data_0x%' "
        "OR name LIKE 'g_state_%' OR name LIKE 'g_unk_%' "
        "ORDER BY address"
    ))
    if not r or not r.get("rows"):
        print("  No generic globals to resolve")
        return

    generics = [(int(row[0]), row[1]) for row in r["rows"]]
    print(f"  {len(generics)} generic globals to resolve")

    # Convert all_code to (name, code) tuples for analysis
    code_tuples = [(name, code) for addr, name, size, code in all_code if code]

    # Get function list for vtable detection
    fr = sql(port, "SELECT address, name FROM funcs")
    func_names = {row[1] for row in fr["rows"]} if fr else set()

    resolved = {}
    for addr, name in generics:
        info = analyze_global_in_code(name, code_tuples)
        new_name = None

        # 1. Try encrypted string context
        api = infer_from_enc_context(name, code_tuples, enc_map)
        if api:
            new_name = f"g_pfn{api}"

        # 2. Try call pattern analysis
        if not new_name and info["called"]:
            api = infer_api_from_call(info)
            if api:
                new_name = f"g_pfn{api}"

        # 3. Check if it's a vtable entry (stores a known function pointer)
        if not new_name:
            for fname, line in info.get("assign_lines", []):
                for fn in func_names:
                    if fn in line and fn != name:
                        new_name = f"g_vtable_{fn.replace('vtfn_', '')}"
                        break
                if new_name:
                    break

        # 4. Check if it's a parent context / callback pointer
        if not new_name:
            for fname, line in info.get("assign_lines", []):
                if "lpReserved" in line or "param3" in line.lower():
                    new_name = "g_pParentCtx"
                    break

        # 5. Module handle pattern (result of GetModuleHandleA/LoadLibraryA cached)
        if not new_name:
            for fname, line in info.get("assign_lines", []):
                if "resolve_" in fname and "proc" in fname:
                    new_name = f"g_hModule_{fname.split('_')[1]}"
                    break

        # 6. Heap function pointers
        if not new_name:
            ref_fns = info.get("ref_funcs", [])
            if any("heap_alloc" in f for f in ref_fns) and not any("heap_free" in f for f in ref_fns):
                new_name = "g_pfnHeapAlloc"
            elif any("heap_free" in f for f in ref_fns):
                new_name = "g_pfnHeapFree"

        # 7. GetModuleHandleA / GetProcAddress pattern
        if not new_name and info["called"]:
            ref_fns = info.get("ref_funcs", [])
            if any("resolve" in f for f in ref_fns):
                for fname, line in info["call_lines"]:
                    if "resolve" in fname:
                        # Called in resolve_xxx_proc — likely GetModuleHandleA or GetProcAddress
                        m = re.search(r'=\s*' + re.escape(name) + r'\s*\(', line)
                        if m:
                            # This global returns a value used as module handle
                            new_name = "g_pfnGetModuleHandleA"
                        else:
                            new_name = "g_pfnGetProcAddress"
                        break

        # 8. Fallback: if called, it's some function pointer; if data-only, some state
        if not new_name:
            if info["called"]:
                new_name = f"g_pfnUnk_{addr & 0xFFFF:04X}"
            elif info["ref_funcs"]:
                new_name = f"g_unk_{addr & 0xFFFF:04X}"
            else:
                new_name = f"g_unused_{addr & 0xFFFF:04X}"

        resolved[addr] = (name, new_name)

    # Apply renames
    used_names = set()
    for addr, (old, new) in sorted(resolved.items()):
        base = new
        suffix = 2
        while new in used_names:
            new = f"{base}_{suffix}"
            suffix += 1
        used_names.add(new)
        set_name_safe(port, addr, new)
        if not new.startswith("g_pfnUnk_") and not new.startswith("g_unk_") and not new.startswith("g_unused_"):
            print(f"  0x{addr:X}: {old} -> {new}")

    # Count remaining
    r = sql(port, (
        "SELECT count(*) FROM names WHERE "
        "name LIKE 'g_qword_%' OR name LIKE 'g_pfn_0x%' "
        "OR name LIKE 'g_data_0x%' OR name LIKE 'g_state_%'"
    ))
    remaining = int(r["rows"][0][0]) if r else "?"
    print(f"  Resolved {len(resolved)} globals, {remaining} generic remain")
    return resolved


# ---- Step 4: Generate C Source ----

def step_generate_c(port, blob_num, name, funcs_data=None):
    """Decompile all functions and generate clean .c file."""
    print("\n--- Step 4: Generate clean .c ---")

    if funcs_data is None:
        funcs_data = decompile_all(port)

    # Force re-decompile to pick up all renames
    funcs_data_fresh = []
    for addr, fname, size, _ in funcs_data:
        d = sql(port, f"SELECT decompile({addr}, 1)", timeout=300)
        code = d["rows"][0][0] if d and d.get("rows") and d["rows"][0][0] else f"// decompilation failed for {fname}"
        funcs_data_fresh.append((addr, fname, size, code))

    parts = [
        f"/* blob_{blob_num}_{name}.c",
        f" * ScatterBrain plugin: {name}",
        f" * {len(funcs_data_fresh)} functions",
        " * Auto-generated from IDA decompilation",
        " */\n",
    ]

    for addr, fname, size, code in funcs_data_fresh:
        # Strip IDA artifacts
        lines = code.split("\n")
        clean = []
        for line in lines:
            line = re.sub(r'/\*\s*[0-9A-Fa-f]+\s*\*/', '', line)
            line = re.sub(r'/\*\s+\*/', '', line)
            line = re.sub(r'\s*\[lv:\d+\]', '', line)
            clean.append(line)
        code = "\n".join(clean)

        parts.append(f"/* -- {fname} (0x{addr:X}, {size} bytes) {'--' * 20} */\n")
        parts.append(code)
        parts.append("")

    c_source = "\n".join(parts)

    out_path = os.path.join(BASE, "src", "blobs", f"blob_{blob_num}_{name}.c")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(c_source)
    print(f"  Wrote {len(c_source)} bytes to {out_path}")

    # Quality check
    for pattern, label in [
        (r'\bqword_[0-9A-Fa-f]+\b', 'qword_[hex]'),
        (r'\bg_qword_\w+', 'g_qword_'),
        (r'\bg_pfn_0x\w+', 'g_pfn_0x'),
        (r'\bg_data_0x\w+', 'g_data_0x'),
        (r'\bg_state_\w+', 'g_state_'),
        (r'\bsub_[0-9A-Fa-f]+\b', 'sub_'),
        (r'\bbyte_[0-9A-Fa-f]{4,}\b', 'byte_[hex]'),
        (r'\bdword_[0-9A-Fa-f]{4,}\b', 'dword_[hex]'),
    ]:
        count = len(re.findall(pattern, c_source))
        if count > 0:
            print(f"  WARNING: {count} x {label}")

    return c_source


# ---- Main Pipeline ----

def deep_annotate(blob_num, port, do_launch=False, do_shutdown=False):
    name = BLOB_META[blob_num]["name"]
    print(f"\n{'='*60}")
    print(f"  blob_{blob_num} ({name}) -- port {port}")
    print(f"{'='*60}")

    proc = None
    if do_launch:
        if not wait_for_server(port, max_wait=3):
            proc = launch_server(blob_num, port, name)
            if not proc:
                return False
    else:
        if not wait_for_server(port, max_wait=5):
            print(f"  ERROR: No server on port {port}", file=sys.stderr)
            return False

    try:
        enc_strings = load_encrypted_strings(blob_num)
        known_imports = load_imports(blob_num)
        print(f"  {len(enc_strings)} encrypted strings, {len(known_imports)} imports")

        # Step 1: Hash enum
        step_hash_enum(port)

        # Step 2: Encrypted strings
        step_encrypted_strings(port, enc_strings)

        # Step 3: Decompile + resolve globals
        print("\n--- Decompiling all functions ---")
        all_code = decompile_all(port)
        print(f"  Decompiled {len(all_code)} functions")

        step_resolve_globals(port, enc_strings, all_code)

        # Step 4: Save IDB
        print("\n--- Saving IDB ---")
        sql(port, "SELECT save_database()")
        print("  IDB saved")

        # Step 5: Generate clean .c
        step_generate_c(port, blob_num, name, all_code)

        return True

    finally:
        if do_shutdown:
            try:
                requests.post(f"http://127.0.0.1:{port}/shutdown", timeout=10)
            except:
                pass
            if proc:
                try:
                    proc.wait(timeout=30)
                except:
                    proc.kill()
            print(f"  Server shut down")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--blob", type=int, required=True)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--launch", action="store_true", help="Launch idasql server")
    parser.add_argument("--shutdown", action="store_true", help="Shutdown server when done")
    args = parser.parse_args()

    if args.blob not in BLOB_META:
        print(f"Invalid blob: {args.blob}", file=sys.stderr)
        sys.exit(1)

    port = args.port or (8200 + args.blob)
    ok = deep_annotate(args.blob, port, args.launch, args.shutdown)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
