"""
Brute-force resolve API hashes against Windows DLL exports.

Reads hash algorithm parameters and known hashes from a JSON profile
(default: profiles/scatterbrain.json). Supports pluggable hash algorithms
so the same script works for different obfuscator families.

Usage:
    python scripts/hash_resolve.py                                  # use default profile
    python scripts/hash_resolve.py --profile profiles/other.json    # custom profile
    python scripts/hash_resolve.py --hash 0xBDA26FE6                # resolve one hash
    python scripts/hash_resolve.py --dll C:\\Windows\\System32\\kernel32.dll
    python scripts/hash_resolve.py --all-exports                    # dump all hashes
"""

import argparse
import json
import sys
from pathlib import Path

import lief

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PROFILE = SCRIPT_DIR / "profiles" / "scatterbrain.json"
MASK32 = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Hash algorithms (pluggable by profile)
# ---------------------------------------------------------------------------

def ror4(val, bits):
    """32-bit rotate right."""
    val &= MASK32
    return ((val >> bits) | (val << (32 - bits))) & MASK32


def make_hash_func(algo_cfg: dict):
    """
    Build module and export hash functions from profile config.
    Returns (hash_module, hash_export) callables.
    """
    algo_type = algo_cfg.get("type", "ror8_xor")
    xor_const = int(algo_cfg.get("xor_constant", "0"), 16)
    rot_bits = algo_cfg.get("rotate_bits", 8)

    if algo_type != "ror8_xor":
        raise ValueError(f"Unsupported hash algorithm type: {algo_type}")

    def hash_wide_ci(name: str) -> int:
        h = 0
        for c in name:
            b = ord(c) & 0xFF
            b |= 0x20
            h = ((b + ror4(h, rot_bits)) ^ xor_const) & MASK32
        return h

    def hash_ascii(name: str) -> int:
        h = 0
        for c in name:
            h = ((ord(c) + ror4(h, rot_bits)) ^ xor_const) & MASK32
        return h

    return hash_wide_ci, hash_ascii


# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------

def load_profile(path: Path) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def hashes_from_profile(profile: dict) -> dict:
    """Extract {int_hash: (type, description)} from profile known_hashes."""
    out = {}
    for htype in ("module", "export"):
        entries = profile.get("known_hashes", {}).get(htype, {})
        for hex_hash, name in entries.items():
            h = int(hex_hash, 16)
            out[h] = (htype, name)
    return out


def dlls_from_profile(profile: dict) -> list[str]:
    return profile.get("dll_search_paths", [])


# ---------------------------------------------------------------------------
# Resolution engine
# ---------------------------------------------------------------------------

def resolve_hashes(target_hashes: set, dll_paths: list[str],
                   hash_module, hash_export) -> dict:
    """
    Brute-force resolve hashes against DLL exports.
    Returns dict: hash_value -> list of (dll_name, export_name, hash_type)
    """
    results = {}

    for dll_path in dll_paths:
        p = Path(dll_path)
        if not p.exists():
            print(f"[!] Skipping {dll_path} (not found)", file=sys.stderr)
            continue

        dll_name = p.name

        # Check module name hash (full name and stem)
        for variant in (dll_name, p.stem):
            h = hash_module(variant)
            if h in target_hashes:
                tag = "module" if variant == dll_name else "module_stem"
                results.setdefault(h, []).append((dll_name, variant, tag))

        # Parse exports
        try:
            pe = lief.parse(str(p))
            if pe is None or not pe.has_exports:
                continue
        except Exception as e:
            print(f"[!] Failed to parse {dll_path}: {e}", file=sys.stderr)
            continue

        for export in pe.get_export().entries:
            if not export.name:
                continue
            h = hash_export(export.name)
            if h in target_hashes:
                results.setdefault(h, []).append((dll_name, export.name, "export"))

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Resolve obfuscated API hashes against Windows DLL exports"
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=DEFAULT_PROFILE,
        help=f"JSON profile with hash algo + known hashes (default: {DEFAULT_PROFILE.name})",
    )
    parser.add_argument(
        "--hash",
        type=lambda s: int(s, 16) if s.startswith("0x") else int(s),
        action="append",
        default=None,
        help="Specific hash(es) to resolve (hex). Can be repeated.",
    )
    parser.add_argument(
        "--dll",
        action="append",
        default=None,
        help="Specific DLL path(s) to search. Can be repeated.",
    )
    parser.add_argument(
        "--all-exports",
        action="store_true",
        help="Print all export hashes (for building a hash table)",
    )

    args = parser.parse_args()

    # Load profile
    profile = load_profile(args.profile)
    known = hashes_from_profile(profile)
    hash_module, hash_export = make_hash_func(profile.get("hash_algorithm", {}))

    print(f"[*] Profile: {profile.get('name', args.profile.name)}", file=sys.stderr)

    # Target hashes
    if args.hash:
        target_hashes = set(args.hash)
    else:
        target_hashes = set(known.keys())

    dll_paths = args.dll if args.dll else dlls_from_profile(profile)

    print(f"[*] Resolving {len(target_hashes)} hash(es) against {len(dll_paths)} DLL(s)...",
          file=sys.stderr)

    # Dump mode
    if args.all_exports:
        for dll_path in dll_paths:
            p = Path(dll_path)
            if not p.exists():
                continue
            pe = lief.parse(str(p))
            if pe is None or not pe.has_exports:
                continue
            print(f"\n# {p.name}")
            print(f"# Module hash: 0x{hash_module(p.name):08X}")
            for export in pe.get_export().entries:
                if export.name:
                    h = hash_export(export.name)
                    print(f"0x{h:08X}  {p.name}!{export.name}")
        return

    # Resolve
    results = resolve_hashes(target_hashes, dll_paths, hash_module, hash_export)

    # Print results
    print()
    for h in sorted(target_hashes):
        desc = known.get(h, ("?", "Unknown"))[1]
        print(f"0x{h:08X}  ({desc})")
        if h in results:
            for dll_name, name, htype in results[h]:
                print(f"  -> {dll_name}!{name}  [{htype}]")
        else:
            print("  -> NOT FOUND")
        print()

    resolved = sum(1 for h in target_hashes if h in results)
    print(f"[*] Resolved {resolved}/{len(target_hashes)} hashes.")


if __name__ == "__main__":
    main()
