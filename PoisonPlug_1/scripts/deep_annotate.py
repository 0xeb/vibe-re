#!/usr/bin/env python
"""
deep_annotate.py -- Deep-annotate a single blob IDB via idasql HTTP server.

Renames all g_qword_*/g_byte_*/g_dword_* globals to proper names by:
  1. Mapping encrypted string VAs to enc_* names
  2. Tracing indirect calls to identify API function pointers
  3. Analyzing xrefs for remaining globals

Also creates the api_hash_t enum for PEB hash resolve functions.

Usage:
    python scripts/deep_annotate.py --blob N --port PORT
    python scripts/deep_annotate.py --blob 1 --port 8201
"""

import argparse
import json
import os
import re
import sys
import time
import requests

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BLOB_META = {
    0: {"name": "Install",  "port": 8200},
    1: {"name": "Plugins",  "port": 8201},
    2: {"name": "Config",   "port": 8202},
    3: {"name": "Online",   "port": 8203},
    4: {"name": "TCP",      "port": 8204},
    5: {"name": "HTTP",     "port": 8205},
    6: {"name": "UDP",      "port": 8206},
    7: {"name": "DNS",      "port": 8207},
}

# WS2_32 ordinal mapping
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
            print(f"  SQL ERROR: {j.get('error', 'unknown')} | {query[:80]}", file=sys.stderr)
            return None
        return j
    except Exception as e:
        print(f"  REQUEST ERROR: {e} | {query[:80]}", file=sys.stderr)
        return None


def load_encrypted_strings(blob_num):
    path = os.path.join(BASE, "idb", "blobs", "blob_encrypted_strings.json")
    with open(path) as f:
        data = json.load(f)
    return data.get(f"blob_{blob_num}", [])


def load_imports(blob_num):
    path = os.path.join(BASE, "idb", "blobs", "blob_pe_summary.json")
    with open(path) as f:
        data = json.load(f)
    entry = data[blob_num]
    imports = []
    for dll_entry in entry.get("imports", []):
        dll = dll_entry["dll"]
        for func in dll_entry["functions"]:
            # Resolve WS2_32 ordinals
            if func.startswith("ord#"):
                ordinal = int(func[4:])
                resolved = WS2_32_ORDINALS.get(ordinal, func)
                imports.append((dll, resolved))
            else:
                imports.append((dll, func))
    return imports


def set_name(port, addr, name):
    """Set a name at an address, handling duplicates."""
    safe_name = name.replace("'", "''")
    r = sql(port, f"SELECT set_name({addr}, '{safe_name}')")
    if r is None:
        # Try with suffix for duplicates
        for i in range(2, 10):
            r = sql(port, f"SELECT set_name({addr}, '{safe_name}_{i}')")
            if r:
                return f"{name}_{i}"
    return name


def create_hash_enum(port):
    """Create the api_hash_t enum for PEB hash resolve."""
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
    r = sql(port, f"SELECT parse_decls('{decl}')")
    if r:
        print("  Created api_hash_t enum")
    return r is not None


def apply_hash_enum_to_functions(port):
    """Find hash resolve functions and retype their parameter."""
    r = sql(port, "SELECT address, name FROM funcs WHERE name LIKE '%hash_resolve%' OR name LIKE '%peb_resolve%'")
    if not r or not r.get("rows"):
        print("  No hash resolve functions found")
        return
    for row in r["rows"]:
        addr = int(row[0])
        name = row[1]
        proto = f"void * __fastcall {name}(api_hash_t hash);"
        sql(port, f"UPDATE funcs SET prototype = '{proto}' WHERE address = {addr}")
        sql(port, f"SELECT decompile({addr}, 1)")
        print(f"  Applied api_hash_t to {name} @ 0x{addr:X}")


def get_unnamed_globals(port):
    """Get all globals with generic names (g_qword_*, g_byte_*, etc.)."""
    r = sql(port, (
        "SELECT address, name FROM names "
        "WHERE name LIKE 'g_qword_%' OR name LIKE 'g_byte_%' "
        "OR name LIKE 'g_dword_%' OR name LIKE 'g_word_%' "
        "OR name LIKE 'g_unk_%' "
        "ORDER BY address"
    ))
    if not r:
        return []
    return [(int(row[0]), row[1]) for row in r.get("rows", [])]


def get_xrefs_to(port, addr):
    """Get all code xrefs pointing to an address."""
    r = sql(port, f"SELECT from_ea FROM xrefs WHERE to_ea = {addr}")
    if not r:
        return []
    return [int(row[0]) for row in r.get("rows", [])]


def get_xrefs_from(port, addr):
    """Get all xrefs from an address."""
    r = sql(port, f"SELECT to_ea FROM xrefs WHERE from_ea = {addr}")
    if not r:
        return []
    return [int(row[0]) for row in r.get("rows", [])]


def is_indirect_call_target(port, global_addr):
    """Check if a global is used as an indirect call target (function pointer)."""
    xrefs = get_xrefs_to(port, global_addr)
    for xref_ea in xrefs:
        # Check the instruction at xref_ea — if it's a call, this is an API pointer
        r = sql(port, f"SELECT mnemonic FROM instructions WHERE address = {xref_ea} AND func_addr != 0 LIMIT 1")
        if r and r.get("rows"):
            mnem = r["rows"][0][0]
            if mnem and "call" in mnem.lower():
                return True
    return False


def trace_api_name_from_context(port, global_addr, enc_strings_by_va, known_imports):
    """Try to determine the API name for a function pointer global by analyzing context."""
    # Strategy 1: Check if this global is written near a decrypt_string + GetProcAddress pattern
    # Look at the write xrefs (who writes to this global)
    r = sql(port, f"SELECT from_ea FROM xrefs WHERE to_ea = {global_addr} AND is_code = 0")
    if not r:
        r = sql(port, f"SELECT from_ea FROM xrefs WHERE to_ea = {global_addr}")
    if not r or not r.get("rows"):
        return None

    # For each write site, check surrounding context for encrypted strings
    for row in r["rows"]:
        from_ea = int(row[0])
        func_addr = get_containing_func(port, from_ea)
        if func_addr is None:
            continue

        # Check nearby encrypted string references in the same function
        # Look at the pseudocode around this EA
        ps = sql(port, f"SELECT ea, line FROM pseudocode WHERE func_addr = {func_addr} AND ea BETWEEN {from_ea - 64} AND {from_ea + 64}")
        if not ps or not ps.get("rows"):
            continue

        for ps_row in ps["rows"]:
            line = ps_row[1] if ps_row[1] else ""
            # Look for encrypted string references in the line
            for enc_va, enc_name in enc_strings_by_va.items():
                enc_va_hex = f"0x{enc_va:X}"
                if enc_va_hex.lower() in line.lower() or f"enc_{enc_name}" in line:
                    # This API pointer is likely the one named by the encrypted string
                    return enc_name

    return None


def get_containing_func(port, ea):
    """Get the function containing an EA."""
    r = sql(port, f"SELECT func_start({ea})")
    if r and r.get("rows") and r["rows"][0][0]:
        val = r["rows"][0][0]
        if val and str(val) != "None" and str(val) != "":
            return int(val)
    return None


def name_globals(port, blob_num, enc_strings, known_imports):
    """Name all generic globals with meaningful names."""
    unnamed = get_unnamed_globals(port)
    if not unnamed:
        print("  No unnamed globals to process")
        return 0

    print(f"  {len(unnamed)} generically-named globals to process")

    # Build encrypted string VA lookup
    enc_by_va = {}
    for s in enc_strings:
        va = int(s["va"], 16)
        dec = s["decrypted"]
        # Clean the name for IDA
        clean = re.sub(r'[^a-zA-Z0-9_]', '_', dec)[:40]
        enc_by_va[va] = clean

    # Build import name set for matching
    import_names = set()
    for dll, func in known_imports:
        import_names.add(func)

    renamed = 0
    used_names = set()

    for addr, old_name in unnamed:
        new_name = None

        # Check if it's near an encrypted string (within 0x10 bytes of an enc_ address)
        for enc_va, enc_clean in enc_by_va.items():
            if abs(addr - enc_va) < 0x10 and addr != enc_va:
                # This is likely the resolved function pointer for the encrypted string's API
                api_name = enc_clean
                new_name = f"g_pfn{api_name}"
                break

        if new_name is None:
            # Check if it's an indirect call target (API function pointer)
            if is_indirect_call_target(port, addr):
                # Try to match with known imports by position
                new_name = f"g_pfn_0x{addr & 0xFFFF:04X}"
            else:
                # It's a data global, not a function pointer
                # Check usage context
                xrefs = get_xrefs_to(port, addr)
                if len(xrefs) == 0:
                    new_name = f"g_unused_0x{addr & 0xFFFF:04X}"
                else:
                    new_name = f"g_data_0x{addr & 0xFFFF:04X}"

        # Ensure uniqueness
        base_name = new_name
        suffix = 2
        while new_name in used_names:
            new_name = f"{base_name}_{suffix}"
            suffix += 1
        used_names.add(new_name)

        actual = set_name(port, addr, new_name)
        if actual != old_name:
            renamed += 1

    print(f"  Renamed {renamed} globals")
    return renamed


def identify_framework_imports(port, blob_num, known_imports):
    """Try to map framework-resolved API pointers to their import names."""
    if not known_imports:
        return

    # Find all g_pfn_* globals that are indirect call targets
    r = sql(port, "SELECT address, name FROM names WHERE name LIKE 'g_pfn_0x%' ORDER BY address")
    if not r or not r.get("rows"):
        return

    pfn_globals = [(int(row[0]), row[1]) for row in r["rows"]]

    # Find consecutive blocks of API pointers (framework fills them sequentially)
    # Group by proximity (within 0x100 bytes)
    groups = []
    current_group = []
    for addr, name in pfn_globals:
        if current_group and addr - current_group[-1][0] > 0x10:
            if len(current_group) >= 3:
                groups.append(current_group)
            current_group = []
        current_group.append((addr, name))
    if len(current_group) >= 3:
        groups.append(current_group)

    # For the largest consecutive group, try to map to imports
    if not groups:
        return

    largest = max(groups, key=len)
    print(f"  Found {len(largest)} consecutive API pointers starting at 0x{largest[0][0]:X}")

    if len(largest) == len(known_imports):
        print(f"  Perfect match with {len(known_imports)} known imports!")
        for (addr, old_name), (dll, api_name) in zip(largest, known_imports):
            new_name = f"g_pfn{api_name}"
            set_name(port, addr, new_name)
            print(f"    0x{addr:X}: {old_name} -> {new_name}")
    elif len(largest) >= len(known_imports):
        print(f"  {len(largest)} globals vs {len(known_imports)} imports — partial mapping")
        # Map as many as we can
        for i, (addr, old_name) in enumerate(largest):
            if i < len(known_imports):
                dll, api_name = known_imports[i]
                new_name = f"g_pfn{api_name}"
                set_name(port, addr, new_name)


def rename_locals_for_function(port, func_addr):
    """Rename generic local variables for a single function."""
    r = sql(port, f"SELECT idx, name, type, is_arg FROM ctree_lvars WHERE func_addr = {func_addr}")
    if not r or not r.get("rows"):
        return 0

    renamed = 0
    for row in r["rows"]:
        idx = int(row[0])
        name = row[1] or ""
        typ = row[2] or ""
        is_arg = int(row[3]) if row[3] else 0

        # Skip already-named variables
        if not re.match(r'^(v\d+|a\d+|result)$', name):
            continue

        # Infer a better name based on type and position
        new_name = None
        if is_arg:
            if "int64" in typ.lower() or typ == "__int64":
                new_name = f"param{idx + 1}"
            elif "char" in typ.lower() or "wchar" in typ.lower():
                new_name = f"str_param{idx + 1}"
            elif "void" in typ.lower() and "*" in typ:
                new_name = f"ptr_param{idx + 1}"
            else:
                new_name = f"param{idx + 1}"
        else:
            if name == "result":
                continue  # Leave result alone
            if "HKEY" in typ or "hkey" in typ.lower():
                new_name = f"hKey{idx}"
            elif "HANDLE" in typ:
                new_name = f"handle{idx}"
            elif typ in ("BOOL", "bool", "_BOOL4", "_BOOL8"):
                new_name = f"bResult{idx}"
            elif "char" in typ.lower() and "*" in typ:
                new_name = f"str{idx}"
            elif "wchar" in typ.lower() and "*" in typ:
                new_name = f"wstr{idx}"
            elif typ in ("int", "unsigned int", "DWORD", "unsigned __int32"):
                new_name = f"dw{idx}"
            elif typ in ("__int64", "unsigned __int64", "size_t"):
                new_name = f"val{idx}"
            elif "*" in typ:
                new_name = f"ptr{idx}"
            else:
                new_name = f"local{idx}"

        if new_name and new_name != name:
            safe = new_name.replace("'", "''")
            sql(port, f"SELECT rename_lvar({func_addr}, {idx}, '{safe}')")
            renamed += 1

    return renamed


def decompile_all_functions(port):
    """Decompile all functions and return list of (addr, name, size, code)."""
    r = sql(port, "SELECT address, name, size FROM funcs ORDER BY address")
    if not r or not r.get("rows"):
        return []

    results = []
    for row in r["rows"]:
        addr = int(row[0])
        name = row[1]
        size = int(row[2]) if row[2] else 0

        d = sql(port, f"SELECT decompile({addr}, 1)", timeout=300)
        if d and d.get("rows") and d["rows"][0][0]:
            code = d["rows"][0][0]
            results.append((addr, name, size, code))
        else:
            results.append((addr, name, size, f"// decompilation failed for {name}"))

    return results


def strip_ida_artifacts(code):
    """Strip IDA address prefixes and artifacts from decompiled code."""
    lines = code.split("\n")
    clean = []
    for line in lines:
        # Remove /* 180001234 */ prefixes
        line = re.sub(r'/\*\s*[0-9A-Fa-f]+\s*\*/', '', line)
        # Remove /*          */ empty prefixes
        line = re.sub(r'/\*\s+\*/', '', line)
        # Remove [lv:N] hints
        line = re.sub(r'\s*\[lv:\d+\]', '', line)
        clean.append(line)
    return "\n".join(clean)


def assemble_c_file(blob_num, name, functions):
    """Assemble a clean .c file from decompiled functions."""
    parts = []
    parts.append(f"/* blob_{blob_num}_{name}.c")
    parts.append(f" * ScatterBrain plugin: {name}")
    parts.append(f" * {len(functions)} functions")
    parts.append(f" * Auto-generated from IDA decompilation")
    parts.append(f" */\n")

    for addr, fname, size, code in functions:
        code = strip_ida_artifacts(code)
        parts.append(f"/* -- {fname} (0x{addr:X}, {size} bytes) {'--' * 20} */\n")
        parts.append(code)
        parts.append("")

    return "\n".join(parts)


def deep_annotate_blob(blob_num, port):
    meta = BLOB_META[blob_num]
    name = meta["name"]

    print(f"\n{'='*60}")
    print(f"  Deep-annotating blob_{blob_num} ({name}) on port {port}")
    print(f"{'='*60}")

    # Verify server is running
    try:
        r = requests.get(f"http://127.0.0.1:{port}/status", timeout=5)
        if r.status_code != 200:
            print(f"  ERROR: Server not ready on port {port}", file=sys.stderr)
            return False
    except:
        print(f"  ERROR: Cannot reach server on port {port}", file=sys.stderr)
        return False

    # Load reference data
    enc_strings = load_encrypted_strings(blob_num)
    known_imports = load_imports(blob_num)
    print(f"  {len(enc_strings)} encrypted strings, {len(known_imports)} known imports")

    # Step 1: Create hash enum
    print("\n--- Step 1: Hash enum ---")
    create_hash_enum(port)
    apply_hash_enum_to_functions(port)

    # Step 2: Name encrypted string globals
    print("\n--- Step 2: Encrypted string globals ---")
    for s in enc_strings:
        va = int(s["va"], 16)
        dec = s["decrypted"]
        clean = re.sub(r'[^a-zA-Z0-9_]', '_', dec)[:40]
        enc_name = f"enc_{clean}"

        # Check if already named
        r = sql(port, f"SELECT name FROM names WHERE address = {va}")
        if r and r.get("rows"):
            existing = r["rows"][0][0]
            if existing and existing.startswith("enc_"):
                continue

        set_name(port, va, enc_name)

    # Step 3: Name remaining globals
    print("\n--- Step 3: Name generic globals ---")
    renamed = name_globals(port, blob_num, enc_strings, known_imports)

    # Step 4: Try to map framework API pointers
    print("\n--- Step 4: Map framework API pointers ---")
    identify_framework_imports(port, blob_num, known_imports)

    # Step 5: Rename locals for all functions
    print("\n--- Step 5: Rename locals ---")
    funcs_r = sql(port, "SELECT address, name, size FROM funcs ORDER BY size DESC")
    total_locals = 0
    if funcs_r and funcs_r.get("rows"):
        for row in funcs_r["rows"]:
            func_addr = int(row[0])
            n = rename_locals_for_function(port, func_addr)
            total_locals += n
    print(f"  Renamed {total_locals} local variables")

    # Step 6: Verify
    print("\n--- Step 6: Verify ---")
    r = sql(port, "SELECT count(*) FROM names WHERE name LIKE 'g_qword_%' OR name LIKE 'g_byte_%' OR name LIKE 'g_dword_%'")
    if r and r.get("rows"):
        remaining = int(r["rows"][0][0])
        print(f"  Remaining generic globals: {remaining}")

    # Step 7: Save
    print("\n--- Step 7: Save IDB ---")
    sql(port, "SELECT save_database()")
    print("  IDB saved")

    # Step 8: Decompile all and produce .c file
    print("\n--- Step 8: Decompile and produce .c ---")
    functions = decompile_all_functions(port)
    c_source = assemble_c_file(blob_num, name, functions)

    out_path = os.path.join(BASE, "src", "blobs", f"blob_{blob_num}_{name}.c")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(c_source)
    print(f"  Wrote {len(c_source)} bytes to {out_path}")

    # Final count
    for pattern in ["qword_", "byte_", "dword_", "__int64 a"]:
        count = c_source.count(pattern)
        if count > 0:
            print(f"  WARNING: {count} occurrences of '{pattern}' remain in output")

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--blob", type=int, required=True)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    blob_num = args.blob
    if blob_num not in BLOB_META:
        print(f"Invalid blob: {blob_num}", file=sys.stderr)
        sys.exit(1)

    port = args.port or BLOB_META[blob_num]["port"]
    ok = deep_annotate_blob(blob_num, port)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
