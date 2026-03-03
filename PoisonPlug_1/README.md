# PoisonPlug / ScatterBrain RE Corpus (Variant 1)

Reverse-engineering corpus for sample SHA-256  
`60678e352f3c849e36413f5de51b5eeca1180840c818f9ece0a0da803eb205a5`.

This repo focuses on static analysis, unpacking workflow automation, and plugin-level documentation.

## At A Glance

- Sample family: ScatterBrain / PoisonPlug-style modular implant
- Plugin set analyzed: `blob_0` through `blob_7`
- Major outputs: architecture docs, per-blob reports, decryption/reconstruction scripts, IDA DB artifacts
- Primary analysis mode: query-first `idasql` workflow over IDA databases
- Full narrative writeup: [docs/scatterbrain_analysis.md](docs/scatterbrain_analysis.md)

## Tooling and Workflow

- Core tools: `idasql`, IDA Pro + Hex-Rays Decompiler, and Claude Code (Opus 4.6)
- Workflow style: `idasql` is the primary analysis interface, with automation-driven annotation via `idasql` + Claude Code and no manual GUI-based annotation steps

## Quick Start

- Project map and file index: [docs/index.md](docs/index.md)
- Plugin anatomy (canonical): [docs/how_plugins_work.md](docs/how_plugins_work.md)
- End-to-end execution flow: [docs/execution_walkthrough.md](docs/execution_walkthrough.md)
- Plugin inventory and roles: [docs/blob_index.md](docs/blob_index.md)
- Script usage and workflow details: [scripts/README.md](scripts/README.md)
- Artifact access policy: [ARTIFACT_ACCESS.md](ARTIFACT_ACCESS.md)

## Read Paths

- New to the repo: start with [docs/index.md](docs/index.md), then [docs/static_analysis_summary.md](docs/static_analysis_summary.md)
- Interested in architecture: read [docs/inner_pe_analysis.md](docs/inner_pe_analysis.md) and [docs/packed_pe_analysis.md](docs/packed_pe_analysis.md)
- Interested in plugin behavior: start with [docs/how_plugins_work.md](docs/how_plugins_work.md), then [docs/blob_index.md](docs/blob_index.md) and each `blob_*_analysis.md`
- Interested in automation: use [scripts/README.md](scripts/README.md) plus stage scripts below

## Repository Layout

| Path | Purpose |
|------|---------|
| `docs/` | Analysis reports, architecture references, and the long-form article |
| `scripts/` | Extraction, reconstruction, decryption, and annotation automation (primarily IDA SQL/idasql-oriented) |
| Private archive (not published) | Sensitive IDA databases and malware-derived binary artifacts |
| `snips/` | Decompilation snippets and shared type definitions |

## Analysis Pipeline

Most scripts are tuned for IDA SQL (`idasql`) workflows over IDA `.i64` databases, with extra Python dependencies used by specific stages.

| Stage | Script | Output |
|------|--------|--------|
| 1 | `scripts/sb_extract.py` | Packed blob extracted from host PE |
| 2 | `scripts/sb_reconstruct_pe.py` | Inner PE reconstructed from packed blob |
| 3 | `scripts/decrypt_blobs.py` | Plugin blobs decrypted and decompressed |
| 4 | `scripts/reconstruct_blob_pes.py` | Plugin PE DLLs rebuilt |
| 5 | `scripts/decrypt_strings.py --scan` | Encrypted strings identified and decrypted |
| 6 | `scripts/recover_source.py` | Batch annotation cleanup via idasql |

## Research Scope

- 8 plugin modules documented with friendly file names in `docs/`
- 3 cipher systems analyzed: IMUL, polynomial XOR, rolling XOR
- Loader chain traced from outer `DllMain` through plugin command dispatch

## Variant Dating

The `TimeDateStamp` field at offset `+0x34` in each plugin's `sb_packed_pe_hdr` provides build-time metadata set by the ScatterBrain packer toolchain itself:

| Blob | Timestamp | Decoded (UTC) |
|------|-----------|---------------|
| blob_0 – blob_7 | `0x58AEBA59` – `0x58AEBA91` | 2017-02-23 10:32:57 – 10:33:53 |
| Inner PE | `0x58B1A6B4` | 2017-02-25 15:45:56 |

Three properties of these timestamps suggest they are authentic build artifacts, not fabricated:

1. **56-second monotonic cluster** — all 8 plugin blobs were compiled within 56 seconds, with ~6-second gaps between each, in strict blob-index order. This is consistent with a batch build script iterating through plugins sequentially.
2. **Correct dependency ordering** — the inner PE (which embeds the plugins) was compiled 2 days *after* the plugins it carries. You cannot embed artifacts that don't exist yet.
3. **Packer-level metadata** — these timestamps live in the ScatterBrain packer's custom header format, not the standard PE `IMAGE_FILE_HEADER`. They were recorded by the packer toolchain during the packaging step.

This places the sample as an early-generation ScatterBrain/PoisonPlug variant, compiled years before publicly tracked ScatterBrain activity (2022+). The architecture, cipher systems, and plugin protocol documented here represent a snapshot of the framework at this earlier stage.

## Verification and Limitations

The analysis is grounded in repeatable `idasql` queries over IDA databases and validated against Hex-Rays decompilation output. This provides strong confidence in structure, control-flow interpretation, and plugin protocol mapping.

As with any large-scale reverse engineering workflow, localized inaccuracies may still exist due to decompilation ambiguity, obfuscation edge cases, or tradeoffs made for research throughput. This corpus should be treated as a high-confidence research baseline, well beyond a preliminary or toy `idasql` demonstration, with iterative corrections expected as new edge cases are discovered.

## Artifact Availability

Sensitive malware-derived databases and decrypted binary artifacts are not distributed in this public repository. Access may be granted on request to vetted security researchers and organizations; anonymous requests are not accepted.

## Safety

For malware analysis and defensive research only.

## Prior Work (Context Only)

This research was conducted independently and was not influenced by prior published reports. The two links below were only briefly scanned to obtain malware hashes.

- Google Cloud Threat Intelligence: [ScatterBrain: Unmasking PoisonPlug Obfuscator](https://cloud.google.com/blog/topics/threat-intelligence/scatterbrain-unmasking-poisonplug-obfuscator)
- SecuriTricks Attack Reports: [Unmasking the Shadow of PoisonPlug's Obfuscator](https://securitricks.com/attackreports/unmasking-the-shadow-of-poisonplugs-obfuscator)
