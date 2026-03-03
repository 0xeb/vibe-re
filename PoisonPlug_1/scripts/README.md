# ScatterBrain Analysis Scripts

<a id="scripts-pipeline"></a>
## Pipeline

```
Host PE (.neutred)
  │
  ├─ sb_extract.py ──────────► output/packed_blob.bin, mapped_image.bin, sb_extract.json
  │
  ├─ sb_reconstruct_pe.py ──► output/inner_pe.dll.pe
  │
  ├─ decrypt_blobs.py ──────► output/blobs/blob_N_payload.bin  (×8)
  │
  └─ reconstruct_blob_pes.py ► output/blobs/blob_N_Name.dll.pe (×8)

Any PE DLL
  └─ decrypt_strings.py ────► stdout / JSON (encrypted string inventory)

Host PE obfuscation
  ├─ deobf_sweep.py ────────► NOP patch SQL for opaque predicates
  └─ hash_resolve.py ───────► API hash → name resolution
```

Scripts write to `output/` as a transient scratch workspace. Sensitive malware-derived artifacts are archived in a private workspace outside this public repo.

Primary workflow note: this pipeline is designed to pair with `idasql` as the query-first analysis interface over IDA databases.

<a id="scripts-shared-libraries"></a>
## Shared Libraries

| File | Purpose |
|------|---------|
| `sb_ciphers.py` | 3 cipher implementations: `imul_cipher`, `poly_xor_decrypt_blob`, `import_xor_decrypt_name` |
| `sb_packed_pe.py` | Packed PE parser: `parse_packed_header`, `build_mapped_image`, `extract_imports` |

<a id="scripts-pipeline-scripts"></a>
## Pipeline Scripts

| File | Stage | Input | Output |
|------|-------|-------|--------|
| `sb_extract.py` | 1 | Host PE binary | `packed_blob.bin`, `mapped_image.bin`, `sb_extract.json` |
| `sb_reconstruct_pe.py` | 2 | `packed_blob.bin` + `sb_extract.json` | `inner_pe.dll.pe` (valid PE32+ DLL) |
| `decrypt_blobs.py` | 3 | `inner_pe.dll.pe` | `blob_N_payload.bin` (×8, IMUL + LZ77) |
| `reconstruct_blob_pes.py` | 4 | `blob_N_payload.bin` | `blob_N_Name.dll.pe` (×8, valid PE32+) |

<a id="scripts-standalone-tools"></a>
## Standalone Tools

| File | Purpose |
|------|---------|
| `decrypt_strings.py` | Polynomial XOR string decryptor. `--image any.dll --scan` mode for any PE. |
| `deobf_sweep.py` | Capstone linear sweep — detects and removes opaque predicate anti-disassembly. |
| `hash_resolve.py` | Profile-driven API hash brute-forcer (ROR-8/XOR/0x7C35D9A3). |
| `capstone_disasm.py` | General-purpose Capstone disassembler for raw binary blobs. |

<a id="scripts-profiles"></a>
## Profiles

| File | Purpose |
|------|---------|
| `profiles/scatterbrain.json` | Hash algorithm config + known hashes for ScatterBrain family. |
