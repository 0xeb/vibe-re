#!/usr/bin/env python
"""
recover_structs.py -- Structure recovery for ScatterBrain plugin IDBs.

Follows calls/callers, finds field access patterns (cot_add offsets),
cross-correlates across multiple functions to build struct definitions,
then applies them via idasql.

Usage:
    python scripts/recover_structs.py --blob N [--port PORT]
    python scripts/recover_structs.py --blob -1  # all blobs
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
    0: {"name": "Install",  "port": 8200, "vtable_funcs": 2},
    1: {"name": "Plugins",  "port": 8201, "vtable_funcs": 5},
    2: {"name": "Config",   "port": 8202, "vtable_funcs": 3},
    3: {"name": "Online",   "port": 8203, "vtable_funcs": 14},
    4: {"name": "TCP",      "port": 8204, "vtable_funcs": 6},
    5: {"name": "HTTP",     "port": 8205, "vtable_funcs": 6},
    6: {"name": "UDP",      "port": 8206, "vtable_funcs": 6},
    7: {"name": "DNS",      "port": 8207, "vtable_funcs": 6},
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
        print(f"  ERROR: IDB not found: {idb_path}", file=sys.stderr)
        return None
    cmd = [IDASQL, "-s", idb_path, "--http", str(port)]
    print(f"  Launching: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_for_server(port):
        proc.kill()
        return None
    return proc


# ----------------------------------------------------------------
# Phase 1: Discover vtable/command functions and their context ptr
# ----------------------------------------------------------------

def find_vtable_and_cmd_funcs(port):
    """Find functions that take a context pointer as first arg.
    These are vtfn_*, subcmd_*, cmd_* functions."""
    r = sql(port, """
        SELECT address, name, size FROM funcs
        WHERE name LIKE 'vtfn_%' OR name LIKE 'subcmd_%' OR name LIKE 'cmd_%'
           OR name LIKE 'cmd1_%'
        ORDER BY address
    """)
    if not r or not r.get("rows"):
        return []
    return [(int(row[0]), row[1], int(row[2])) for row in r["rows"]]


def find_all_funcs(port):
    """Get all functions."""
    r = sql(port, "SELECT address, name, size FROM funcs ORDER BY address")
    if not r or not r.get("rows"):
        return []
    return [(int(row[0]), row[1], int(row[2])) for row in r["rows"]]


# ----------------------------------------------------------------
# Phase 2: Extract offset access patterns from decompiled code
# ----------------------------------------------------------------

def extract_offsets_from_decompile(port, func_addr, ctx_var_names=None):
    """Extract pointer arithmetic offsets from decompiled code.
    Returns dict: offset -> list of (access_type, size_hint, context_line)"""
    decomp = sql(port, f"SELECT decompile({func_addr})", timeout=120)
    if not decomp or not decomp.get("rows") or not decomp["rows"][0][0]:
        return {}

    code = decomp["rows"][0][0]
    offsets = defaultdict(list)

    if ctx_var_names is None:
        ctx_var_names = ["ctx", "this_ptr", "a1"]

    # Pattern 1: *(TYPE *)(ctx + OFFSET) -- direct field access with cast
    # e.g. *((_QWORD *)ctx + 5)  -> offset = 5*8 = 0x28
    # e.g. *(_DWORD *)(ctx + 0x10)
    for var in ctx_var_names:
        var_esc = re.escape(var)

        # *(TYPE *)(var + offset)
        for m in re.finditer(
            rf'\*\s*\(\s*(\w[\w\s\*]*\*)\s*\)\s*\(\s*{var_esc}\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)',
            code
        ):
            typ = m.group(1).strip()
            off = int(m.group(2), 0)
            size = guess_size_from_type(typ)
            line = code[max(0, m.start()-20):m.end()+40].strip()
            offsets[off].append(("deref", size, typ, line[:80]))

        # *((TYPE *)var + N) -- pointer arithmetic (offset = N * sizeof(TYPE))
        for m in re.finditer(
            rf'\*\s*\(\s*(\w[\w\s\*]*\*)\s*\)\s*{var_esc}\s*\+\s*(\d+)\s*\)',
            code
        ):
            typ = m.group(1).strip()
            n = int(m.group(2))
            elem_size = guess_size_from_type(typ)
            off = n * elem_size
            line = code[max(0, m.start()-20):m.end()+40].strip()
            offsets[off].append(("ptr_arith", elem_size, typ, line[:80]))

        # var + offset (without deref -- taking address of field)
        for m in re.finditer(
            rf'\b{var_esc}\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\b',
            code
        ):
            off = int(m.group(1), 0)
            if off > 0 and off < 0x2000:
                line = code[max(0, m.start()-20):m.end()+40].strip()
                offsets[off].append(("addr_of", 0, "", line[:80]))

    return dict(offsets)


def guess_size_from_type(typ):
    """Guess element size from a cast type string."""
    t = typ.lower().replace(" ", "")
    if "_qword" in t or "int64" in t or "longlong" in t:
        return 8
    if "_dword" in t or "int32" in t or "int" in t or "long" in t:
        return 4
    if "_word" in t or "short" in t or "int16" in t:
        return 2
    if "_byte" in t or "char" in t or "int8" in t:
        return 1
    if "*" in t:
        return 8  # 64-bit pointers
    return 8  # default for 64-bit


# ----------------------------------------------------------------
# Phase 3: Cross-correlate across functions to build struct layout
# ----------------------------------------------------------------

def build_struct_layout(all_offsets, blob_name):
    """Merge offset info from multiple functions into a struct layout.
    Returns list of (offset, size, field_name, field_type) sorted by offset."""

    # Merge all offset info
    merged = defaultdict(list)
    for func_name, offsets in all_offsets.items():
        for off, accesses in offsets.items():
            for access in accesses:
                merged[off].append((func_name, *access))

    # Build fields
    fields = []
    for off in sorted(merged.keys()):
        accesses = merged[off]

        # Determine best type from accesses
        sizes = [a[2] for a in accesses if a[2] > 0]
        types_seen = [a[3] for a in accesses if a[3]]
        contexts = [a[4] for a in accesses if a[4]]

        # Pick dominant size
        if sizes:
            size = max(set(sizes), key=sizes.count)
        else:
            size = 8  # default 64-bit

        # Pick best type
        field_type = pick_field_type(size, types_seen, contexts, off)

        # Generate field name from context
        field_name = pick_field_name(off, accesses, contexts)

        fields.append((off, size, field_name, field_type))

    return fields


def pick_field_type(size, types_seen, contexts, offset):
    """Pick the best C type for a field."""
    # Check context for hints
    ctx_lower = " ".join(contexts).lower()

    if any("critical_section" in t.lower() for t in types_seen):
        return "CRITICAL_SECTION"
    if any("handle" in c.lower() for c in contexts):
        return "HANDLE"
    if any("socket" in c.lower() for c in contexts):
        return "SOCKET"
    if any("hmodule" in c.lower() or "module" in c.lower() for c in contexts):
        return "HMODULE"

    # Size-based
    type_map = {1: "BYTE", 2: "WORD", 4: "DWORD", 8: "__int64"}
    if size in type_map:
        # Check if it's likely a pointer
        if size == 8 and any("*" in t for t in types_seen):
            return "void *"
        return type_map[size]
    return f"BYTE[{size}]"


def pick_field_name(offset, accesses, contexts):
    """Generate a descriptive field name from access context."""
    ctx_str = " ".join(c for _, *_, c in accesses).lower()

    # Known patterns from ScatterBrain plugins
    known_fields = {
        0x00: "vtable_ptr",
        0x08: "parent_ctx",
        0x10: "flags",
        0x18: "state",
    }
    if offset in known_fields:
        return known_fields[offset]

    # Infer from context clues
    if "critical" in ctx_str or "crit_sec" in ctx_str:
        return f"lock_{offset:03X}"
    if "socket" in ctx_str or "sock" in ctx_str:
        return f"sock_{offset:03X}"
    if "thread" in ctx_str:
        return f"thread_{offset:03X}"
    if "handle" in ctx_str:
        return f"handle_{offset:03X}"
    if "event" in ctx_str:
        return f"event_{offset:03X}"
    if "buffer" in ctx_str or "buf" in ctx_str:
        return f"buf_{offset:03X}"
    if "size" in ctx_str or "len" in ctx_str:
        return f"size_{offset:03X}"
    if "count" in ctx_str:
        return f"count_{offset:03X}"
    if "addr" in ctx_str or "ip" in ctx_str:
        return f"addr_{offset:03X}"
    if "port" in ctx_str:
        return f"port_{offset:03X}"
    if "flag" in ctx_str:
        return f"flags_{offset:03X}"
    if "timeout" in ctx_str:
        return f"timeout_{offset:03X}"

    # Generic
    return f"field_{offset:03X}"


# ----------------------------------------------------------------
# Phase 4: Create struct in IDA and apply to functions
# ----------------------------------------------------------------

def create_struct_in_ida(port, struct_name, fields):
    """Create a struct type in IDA with the given fields."""

    # Build C declaration
    lines = [f"#pragma pack(push, 1)"]
    lines.append(f"typedef struct {struct_name} {{")

    prev_end = 0
    for off, size, name, typ in fields:
        # Insert padding if needed
        gap = off - prev_end
        if gap > 0:
            lines.append(f"    BYTE _pad_{prev_end:03X}[{gap}];")

        if typ.startswith("BYTE["):
            arr_size = int(typ[5:-1])
            lines.append(f"    BYTE {name}[{arr_size}];")
        elif typ == "CRITICAL_SECTION":
            lines.append(f"    CRITICAL_SECTION {name};")
            size = 40  # sizeof(CRITICAL_SECTION) on x64
        else:
            lines.append(f"    {typ} {name};")

        prev_end = off + size

    lines.append(f"}} {struct_name};")
    lines.append("#pragma pack(pop)")

    decl = "\n".join(lines)
    print(f"\n  Struct declaration:\n{decl}\n")

    # Parse into IDA
    safe_decl = decl.replace("'", "''")
    r = sql(port, f"SELECT parse_decls('{safe_decl}')")
    if r:
        print(f"  Struct {struct_name} created in IDA")
        return True
    else:
        print(f"  WARN: Failed to create struct {struct_name}")
        return False


def apply_struct_to_functions(port, struct_name, func_list):
    """Apply the struct type to the first argument of vtable/cmd functions."""
    applied = 0
    for func_addr, func_name, _ in func_list:
        # Check if first arg exists
        lv = sql(port, f"""
            SELECT idx, name, type, is_arg FROM ctree_lvars
            WHERE func_addr = {func_addr} AND is_arg = 1
            ORDER BY idx LIMIT 1
        """)
        if not lv or not lv.get("rows"):
            continue

        first_arg = lv["rows"][0]
        idx = int(first_arg[0])
        old_type = first_arg[2] or ""

        # Only apply if not already typed
        if struct_name in old_type:
            continue

        r = sql(port, f"""
            UPDATE ctree_lvars SET type = '{struct_name} *'
            WHERE func_addr = {func_addr} AND idx = {idx}
        """)
        if r:
            applied += 1

    if applied > 0:
        # Refresh all modified functions
        for func_addr, func_name, _ in func_list:
            sql(port, f"SELECT decompile({func_addr}, 1)")

    print(f"  Applied {struct_name} * to {applied} function first args")
    return applied


# ----------------------------------------------------------------
# Phase 5: Discover callee-based field types (Sudoku step)
# ----------------------------------------------------------------

def analyze_callee_args_for_struct(port, func_addr, ctx_var_names):
    """Analyze what callees receive as arguments derived from ctx.
    This helps identify field types (e.g., if ctx+0x20 is passed to closesocket, it's a SOCKET)."""
    r = sql(port, f"""
        SELECT call_obj_name, call_helper_name, arg_idx, arg_op,
               arg_var_name, arg_num_value
        FROM ctree_call_args
        WHERE func_addr = {func_addr}
        ORDER BY call_ea, arg_idx
    """)
    if not r or not r.get("rows"):
        return {}

    # Group by call
    field_hints = {}  # offset -> suggested_type
    # We'd need more detailed analysis to correlate specific offsets to callee args
    # For now, return empty - the offset extraction handles most cases
    return field_hints


# ----------------------------------------------------------------
# Main pipeline per blob
# ----------------------------------------------------------------

def recover_structs_for_blob(blob_num, port=None):
    meta = BLOB_META[blob_num]
    name = meta["name"]
    if port is None:
        port = meta["port"]

    print(f"\n{'='*60}")
    print(f"  blob_{blob_num} ({name}) -- port {port}")
    print(f"  Structure Recovery")
    print(f"{'='*60}")

    # Check/launch server
    proc = None
    if not wait_for_server(port, max_wait=5):
        proc = launch_idasql(blob_num, port)
        if proc is None:
            return False

    try:
        # Step 1: Find vtable/command functions (context-ptr consumers)
        print("\n  Step 1: Finding vtable/command functions...")
        vtable_funcs = find_vtable_and_cmd_funcs(port)
        all_funcs = find_all_funcs(port)
        print(f"    Found {len(vtable_funcs)} vtable/cmd functions")

        if not vtable_funcs:
            print("  No vtable/cmd functions found, skipping struct recovery")
            sql(port, "SELECT save_database()")
            return True

        # Step 2: Extract offset patterns from all vtable/cmd funcs
        print("\n  Step 2: Extracting offset patterns from vtable/cmd functions...")
        all_offsets = {}
        for func_addr, func_name, func_size in vtable_funcs:
            offsets = extract_offsets_from_decompile(port, func_addr, ["ctx", "this_ptr", "a1"])
            if offsets:
                all_offsets[func_name] = offsets
                off_list = sorted(offsets.keys())
                print(f"    {func_name}: offsets at {', '.join(hex(o) for o in off_list[:8])}"
                      f"{'...' if len(off_list) > 8 else ''}")

        if not all_offsets:
            print("  No offset patterns found")
            sql(port, "SELECT save_database()")
            return True

        # Step 3: Also scan functions that vtable funcs call (callee analysis)
        print("\n  Step 3: Scanning callees of vtable functions...")
        for func_addr, func_name, _ in vtable_funcs:
            callees = sql(port, f"""
                SELECT DISTINCT callee_addr, callee_name FROM disasm_calls
                WHERE func_addr = {func_addr}
                  AND callee_addr != 0
                  AND callee_name NOT LIKE 'g_pfn%'
                  AND callee_name NOT LIKE '__imp_%'
            """)
            if not callees or not callees.get("rows"):
                continue
            for row in callees["rows"]:
                callee_addr = int(row[0])
                callee_name = row[1]
                if callee_name in all_offsets:
                    continue
                # Check if callee also uses a context pointer
                offsets = extract_offsets_from_decompile(port, callee_addr,
                                                         ["ctx", "this_ptr", "a1", "ptr_arg0"])
                if offsets:
                    all_offsets[callee_name] = offsets

        total_unique_offsets = set()
        for offsets in all_offsets.values():
            total_unique_offsets.update(offsets.keys())
        print(f"    Total unique offsets discovered: {len(total_unique_offsets)}")
        print(f"    Functions analyzed: {len(all_offsets)}")

        # Step 4: Build struct layout
        print("\n  Step 4: Building struct layout...")
        fields = build_struct_layout(all_offsets, name)
        print(f"    Generated {len(fields)} fields")
        for off, size, fname, ftype in fields[:20]:
            print(f"      +0x{off:03X} ({size}B): {ftype:20s} {fname}")
        if len(fields) > 20:
            print(f"      ... and {len(fields) - 20} more")

        # Step 5: Create struct in IDA
        struct_name = f"sb_{name.lower()}_ctx_t"
        print(f"\n  Step 5: Creating {struct_name} in IDA...")
        if not create_struct_in_ida(port, struct_name, fields):
            print("  WARN: Struct creation failed, continuing without type application")
        else:
            # Step 6: Apply struct to vtable/cmd function first args
            print(f"\n  Step 6: Applying {struct_name} to function signatures...")
            apply_struct_to_functions(port, struct_name, vtable_funcs)

        # Save
        sql(port, "SELECT save_database()")
        print("\n  IDB saved")
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
            recover_structs_for_blob(i, args.port)
    else:
        if args.blob not in BLOB_META:
            print(f"Invalid blob: {args.blob}", file=sys.stderr)
            sys.exit(1)
        recover_structs_for_blob(args.blob, args.port)


if __name__ == "__main__":
    main()
