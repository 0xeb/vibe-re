#!/usr/bin/env python
"""
surface_strings.py -- Add pseudocode comments at encrypted string reference sites.

For each blob, launches idasql, finds all xrefs to encrypted string addresses,
and adds inline pseudocode comments showing the decrypted value.

Usage:
    python scripts/surface_strings.py --blob N
    python scripts/surface_strings.py --blob -1  # all blobs
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
    0: {"name": "Install",  "port": 8200},
    1: {"name": "Plugins",  "port": 8201},
    2: {"name": "Config",   "port": 8202},
    3: {"name": "Online",   "port": 8203},
    4: {"name": "TCP",      "port": 8204},
    5: {"name": "HTTP",     "port": 8205},
    6: {"name": "UDP",      "port": 8206},
    7: {"name": "DNS",      "port": 8207},
}


def sql(port, query, timeout=60):
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


def load_encrypted_strings(blob_num):
    path = os.path.join(BASE, "idb", "blobs", "blob_encrypted_strings.json")
    with open(path) as f:
        data = json.load(f)
    return data.get(f"blob_{blob_num}", [])


def surface_strings_for_blob(blob_num, port=None):
    meta = BLOB_META[blob_num]
    name = meta["name"]
    if port is None:
        port = meta["port"]

    print(f"\n{'='*60}")
    print(f"  blob_{blob_num} ({name}) -- port {port}")
    print(f"{'='*60}")

    # Check if server already running, launch if not
    proc = None
    if not wait_for_server(port, max_wait=3):
        proc = launch_idasql(blob_num, port)
        if proc is None:
            return False

    try:
        enc_strings = load_encrypted_strings(blob_num)
        if not enc_strings:
            print("  No encrypted strings for this blob")
            return True

        print(f"  {len(enc_strings)} encrypted strings to surface")

        # Get all functions for func_addr resolution
        funcs_r = sql(port, "SELECT address FROM funcs ORDER BY address")
        if not funcs_r or not funcs_r.get("rows"):
            print("  ERROR: No functions found", file=sys.stderr)
            return False
        func_addrs = sorted([int(r[0]) for r in funcs_r["rows"]])

        def find_func_addr(ea):
            """Find the containing function for an EA."""
            # Binary search for the function containing ea
            lo, hi = 0, len(func_addrs) - 1
            result = None
            while lo <= hi:
                mid = (lo + hi) // 2
                if func_addrs[mid] <= ea:
                    result = func_addrs[mid]
                    lo = mid + 1
                else:
                    hi = mid - 1
            return result

        total_comments = 0
        seen_comments = set()  # (func_addr, ea) to avoid duplicates

        for s in enc_strings:
            va = int(s["va"], 16)
            dec = s["decrypted"]

            # Find all xrefs to this encrypted string address
            xrefs_r = sql(port, f"""
                SELECT from_ea FROM xrefs WHERE to_ea = {va}
            """)
            if not xrefs_r or not xrefs_r.get("rows"):
                continue

            for row in xrefs_r["rows"]:
                ref_ea = int(row[0])
                func_addr = find_func_addr(ref_ea)
                if func_addr is None:
                    continue

                key = (func_addr, ref_ea)
                if key in seen_comments:
                    continue
                seen_comments.add(key)

                # Escape the string for SQL
                safe_dec = dec.replace("'", "''").replace("\\", "\\\\")
                comment = f'enc: "{safe_dec}"'

                # Check if there's already a comment at this EA
                existing = sql(port, f"""
                    SELECT comment FROM pseudocode
                    WHERE func_addr = {func_addr} AND ea = {ref_ea}
                    LIMIT 1
                """)
                if existing and existing.get("rows"):
                    old_comment = existing["rows"][0][0]
                    if old_comment and "enc:" in str(old_comment):
                        continue  # Already has an enc comment

                r = sql(port, f"""
                    UPDATE pseudocode SET comment = '{comment}'
                    WHERE func_addr = {func_addr} AND ea = {ref_ea}
                """)
                if r:
                    total_comments += 1

        print(f"  Added {total_comments} encrypted string comments")

        # Save database
        sql(port, "SELECT save_database()")
        print("  IDB saved")
        return True

    finally:
        # Shutdown
        try:
            requests.post(f"http://127.0.0.1:{port}/shutdown", timeout=10)
        except:
            pass
        if proc:
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
            ok = surface_strings_for_blob(i, args.port)
            if not ok:
                print(f"  FAILED: blob_{i}", file=sys.stderr)
    else:
        if args.blob not in BLOB_META:
            print(f"Invalid blob: {args.blob}", file=sys.stderr)
            sys.exit(1)
        ok = surface_strings_for_blob(args.blob, args.port)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
