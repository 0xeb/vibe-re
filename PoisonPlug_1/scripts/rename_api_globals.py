#!/usr/bin/env python
"""
rename_api_globals.py -- Trace lazy-init API resolution patterns and rename globals.

Scans decompiled code for patterns like:
    decrypt_string(local, enc_XXX) -> resolve_api -> g_qword_YYYY = result
to map g_qword_YYYY -> g_pfnXXX.

Also renames vtable globals and known framework pointers.

Usage:
    python scripts/rename_api_globals.py --blob N [--port PORT]
    python scripts/rename_api_globals.py --blob -1  # all blobs
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import requests
from collections import defaultdict

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDASQL = os.environ.get("IDASQL_PATH", "idasql")

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
            err = j.get("error", "?")[:200]
            print(f"    SQL err: {err}", file=sys.stderr)
            return None
        return j
    except Exception as e:
        print(f"    Req fail: {e}", file=sys.stderr)
        return None


def wait_for_server(port, max_wait=90):
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


def launch_idasql(blob_num, port):
    meta = BLOB_META[blob_num]
    name = meta["name"]
    idb_path = os.path.join(BASE, "idb", "blobs", f"blob_{blob_num}_{name}",
                            f"blob_{blob_num}_{name}.dll.pe.i64")
    if not os.path.exists(idb_path):
        print(f"  ERROR: IDB not found", file=sys.stderr)
        return None
    cmd = [IDASQL, "-s", idb_path, "--http", str(port)]
    print(f"  Launching idasql on port {port}...")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_for_server(port):
        proc.kill()
        return None
    return proc


def load_encrypted_strings(blob_num):
    path = os.path.join(BASE, "idb", "blobs", "blob_encrypted_strings.json")
    with open(path) as f:
        data = json.load(f)
    return data.get(f"blob_{blob_num}", [])


def trace_api_globals(port, enc_strings):
    """Trace the lazy-init pattern to find which globals cache which APIs.

    The pattern in decompiled code is typically:
        dec = decrypt_string(local, enc_XXX)
        ret = decrypt_and_resolve(dec, ...)
        g_qword_YYYY = resolve_api_by_name(ret)  // or resolve_api_by_name_ws2, etc.

    We scan all decompiled code for:
    1. References to enc_* globals near resolve_api_* calls
    2. Assignments of resolve results to g_qword_* / g_state_* globals
    """
    # Build enc name -> decrypted value map
    enc_va_to_name = {}
    for s in enc_strings:
        va = int(s["va"], 16)
        dec = s["decrypted"]
        enc_va_to_name[va] = dec

    # Get all enc_* name mappings from IDA
    enc_names = sql(port, "SELECT address, name FROM names WHERE name LIKE 'enc_%' ORDER BY address")
    enc_ida_map = {}  # enc_name -> decrypted value
    if enc_names and enc_names.get("rows"):
        for row in enc_names["rows"]:
            addr = int(row[0])
            name = row[1]
            if addr in enc_va_to_name:
                enc_ida_map[name] = enc_va_to_name[addr]

    # Get all functions
    funcs = sql(port, "SELECT address, name FROM funcs ORDER BY address")
    if not funcs or not funcs.get("rows"):
        return {}

    # For each function, scan decompiled code for the pattern
    global_api_map = {}  # g_qword_XXXX -> API name

    for row in funcs["rows"]:
        func_addr = int(row[0])
        decomp = sql(port, f"SELECT decompile({func_addr})", timeout=120)
        if not decomp or not decomp.get("rows") or not decomp["rows"][0][0]:
            continue
        code = decomp["rows"][0][0]

        # Strategy 1: Find blocks where:
        #   - decrypt_string is called with a known enc_* reference
        #   - result flows through resolve_api_by_name*
        #   - gets stored in a global

        # Look for patterns like: g_xxx = resolve_api_by_name...(...)
        # and nearby decrypt_string(_, enc_YYY) calls
        # Split code into "if (!g_xxx)" lazy-init blocks
        lazy_blocks = re.findall(
            r'if\s*\(\s*!(\w+)\s*\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
            code, re.DOTALL
        )

        for global_name, block in lazy_blocks:
            if not (global_name.startswith("g_qword_") or global_name.startswith("g_state_") or
                    global_name.startswith("g_pfn")):
                continue

            # Find enc_* references in the block
            enc_refs = re.findall(r'\benc_(\w+)', block)
            if not enc_refs:
                continue

            # Find the resolve call
            has_resolve = ("resolve_api" in block or "resolve_import" in block or
                          "decrypt_and_resolve" in block)
            if not has_resolve:
                continue

            # The encrypted string tells us the API name
            for enc_ref in enc_refs:
                enc_full = f"enc_{enc_ref}"
                if enc_full in enc_ida_map:
                    api_name = enc_ida_map[enc_full]
                    # Only map if it looks like an API/function name
                    if api_name and not any(c in api_name for c in " \\/.:"):
                        global_api_map[global_name] = api_name
                        break

        # Strategy 2: Direct assignment pattern
        # g_xxx = resolve_api_by_name(decrypt_and_resolve(decrypt_string(_, enc_YYY), _))
        for m in re.finditer(
            r'(\w+)\s*=\s*(?:resolve_api\w*|peb_resolve\w*)\s*\(',
            code
        ):
            global_name = m.group(1)
            if not (global_name.startswith("g_qword_") or global_name.startswith("g_state_") or
                    global_name.startswith("g_pfn")):
                continue
            if global_name in global_api_map:
                continue

            # Look backward from this assignment for the nearest enc_* reference
            start_pos = max(0, m.start() - 300)
            context = code[start_pos:m.end()]
            enc_refs = re.findall(r'\benc_(\w+)', context)
            if enc_refs:
                enc_full = f"enc_{enc_refs[-1]}"  # closest one
                if enc_full in enc_ida_map:
                    api_name = enc_ida_map[enc_full]
                    if api_name and not any(c in api_name for c in " \\/.:"):
                        global_api_map[global_name] = api_name

    return global_api_map


def rename_vtable_entries(port):
    """Rename vtable globals based on DllMain_dispatcher assignments."""
    # Find DllMain or dispatcher function
    r = sql(port, """
        SELECT address FROM funcs
        WHERE name LIKE '%DllMain%' OR name LIKE '%dispatcher%'
        ORDER BY size DESC LIMIT 1
    """)
    if not r or not r.get("rows"):
        return 0

    func_addr = int(r["rows"][0][0])
    decomp = sql(port, f"SELECT decompile({func_addr})", timeout=120)
    if not decomp or not decomp.get("rows") or not decomp["rows"][0][0]:
        return 0

    code = decomp["rows"][0][0]
    renamed = 0

    # Find vtable assignments: g_state_XXXX = (type)func_name
    for m in re.finditer(r'(g_state_\w+)\s*=\s*\([^)]*\)\s*(\w+)\s*;', code):
        global_name = m.group(1)
        func_name = m.group(2)
        # Avoid stutter: if func_name already starts with vtfn_, don't add g_vtfn_ prefix
        if func_name.startswith("vtfn_"):
            new_name = f"g_{func_name}"
        elif func_name.startswith("j_"):
            new_name = f"g_vtfn_{func_name[2:]}"
        else:
            new_name = f"g_vtfn_{func_name}"
        if len(new_name) > 63:
            new_name = new_name[:63]

        # Get address of the global
        addr_r = sql(port, f"SELECT address FROM names WHERE name = '{global_name}' LIMIT 1")
        if not addr_r or not addr_r.get("rows"):
            continue
        addr = int(addr_r["rows"][0][0])

        r2 = sql(port, f"SELECT set_name({addr}, '{new_name}')")
        if r2:
            renamed += 1
            print(f"    {global_name} -> {new_name}")

    return renamed


def rename_framework_globals(port, blob_num):
    """Rename known framework globals based on DllMain_dispatcher patterns."""
    # Find DllMain
    r = sql(port, """
        SELECT address FROM funcs
        WHERE name LIKE '%DllMain%' OR name LIKE '%dispatcher%'
        ORDER BY size DESC LIMIT 1
    """)
    if not r or not r.get("rows"):
        return 0

    func_addr = int(r["rows"][0][0])
    decomp = sql(port, f"SELECT decompile({func_addr})", timeout=120)
    if not decomp or not decomp.get("rows") or not decomp["rows"][0][0]:
        return 0

    code = decomp["rows"][0][0]
    renamed = 0

    # Pattern: fdwReason == 100 -> g_xxx = lpReserved (framework context)
    # Look for the specific case: g_qword_XXX = (type)lpReserved in the 100 branch
    for m in re.finditer(r'(g_qword_\w+)\s*=\s*\([^)]*\)\s*lpReserved\s*;', code):
        global_name = m.group(1)
        addr_r = sql(port, f"SELECT address FROM names WHERE name = '{global_name}' LIMIT 1")
        if addr_r and addr_r.get("rows"):
            addr = int(addr_r["rows"][0][0])
            r2 = sql(port, f"SELECT set_name({addr}, 'g_framework_ctx')")
            if r2:
                renamed += 1
                print(f"    {global_name} -> g_framework_ctx")

    return renamed


def rename_api_globals_for_blob(blob_num, port=None):
    meta = BLOB_META[blob_num]
    name = meta["name"]
    if port is None:
        port = meta["port"]

    print(f"\n{'='*60}")
    print(f"  blob_{blob_num} ({name}) -- port {port}")
    print(f"  Rename API Globals")
    print(f"{'='*60}")

    proc = None
    if not wait_for_server(port, max_wait=5):
        proc = launch_idasql(blob_num, port)
        if proc is None:
            return False

    try:
        enc_strings = load_encrypted_strings(blob_num)

        # Step 1: Rename vtable entries
        print("\n  Step 1: Rename vtable entries...")
        vt_renamed = rename_vtable_entries(port)
        print(f"    Renamed {vt_renamed} vtable entries")

        # Step 2: Rename framework context pointer
        print("\n  Step 2: Rename framework globals...")
        fw_renamed = rename_framework_globals(port, blob_num)
        print(f"    Renamed {fw_renamed} framework globals")

        # Step 3: Trace API resolution patterns
        print("\n  Step 3: Tracing API resolution patterns...")
        api_map = trace_api_globals(port, enc_strings)
        print(f"    Found {len(api_map)} global -> API mappings")

        # Apply renames
        applied = 0
        seen_names = set()
        for global_name, api_name in sorted(api_map.items()):
            # Get address
            addr_r = sql(port, f"SELECT address FROM names WHERE name = '{global_name}' LIMIT 1")
            if not addr_r or not addr_r.get("rows"):
                continue
            addr = int(addr_r["rows"][0][0])

            new_name = f"g_pfn{api_name}"
            if new_name in seen_names:
                new_name = f"g_pfn{api_name}_{addr & 0xFFFF:04X}"
            seen_names.add(new_name)

            r2 = sql(port, f"SELECT set_name({addr}, '{new_name}')")
            if r2:
                applied += 1
                print(f"    {global_name} -> {new_name}")

        print(f"\n  Applied {applied} API global renames")

        # Step 4: Count remaining generic globals
        remaining = sql(port, """
            SELECT count(*) FROM names
            WHERE name LIKE 'g_qword_%' OR name LIKE 'g_state_%'
               OR name LIKE 'g_dword_%' OR name LIKE 'g_ptr_%'
               OR name LIKE 'g_data_%'
        """)
        if remaining and remaining.get("rows"):
            count = int(remaining["rows"][0][0])
            print(f"\n  Remaining generic globals: {count}")

        # Save
        sql(port, "SELECT save_database()")
        print("  IDB saved")
        return True

    finally:
        if proc:
            try:
                requests.post(f"http://127.0.0.1:{port}/shutdown", timeout=10)
            except:
                pass
            try:
                proc.wait(timeout=30)
            except:
                proc.kill()
        print(f"  Done: blob_{blob_num}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--blob", type=int, required=True)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    if args.blob == -1:
        for i in range(8):
            rename_api_globals_for_blob(i, args.port)
    else:
        if args.blob not in BLOB_META:
            print(f"Invalid blob: {args.blob}", file=sys.stderr)
            sys.exit(1)
        rename_api_globals_for_blob(args.blob, args.port)


if __name__ == "__main__":
    main()
