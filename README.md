# vibe-re

Reverse-engineering workspace for security-focused research projects, with a strong emphasis on query-driven analysis workflows using [idasql](https://github.com/0xeb/idasql) and [ghidrasql](https://github.com/0xeb/ghidrasql).

## Tools

| Tool | Platform | Description |
|------|----------|-------------|
| [idasql](https://github.com/0xeb/idasql) | IDA Pro | SQL interface for IDA — query functions, xrefs, strings, types, and decompiler output via SQL. |
| [ghidrasql](https://github.com/0xeb/ghidrasql) | Ghidra | SQL interface for Ghidra — same query-driven workflow, headless HTTP mode, write operations (rename, retype, comment).  |

Both tools turn reverse engineering into a data problem: instead of clicking through a GUI, you write SQL queries to explore binaries, annotate findings, and automate analysis.

## Projects

| Project | Description | Analysis Tool | Start Here |
|---------|-------------|--------------|------------|
| `PoisonPlug_1/` | ScatterBrain/PoisonPlug variant — architecture, 8 plugins, 3 ciphers, automation pipeline | idasql | [PoisonPlug_1/README.md](PoisonPlug_1/README.md) |
| `sysinternals_handle64/` | Security audit of the Process Explorer kernel driver (PROCEXP152.sys) — 16 IOCTLs, kernel memory read, PPL bypass, live ntoskrnl dump | ghidrasql | [sysinternals_handle64/README.md](sysinternals_handle64/README.md) |
| `OceanDrift/` | Graph API / OneDrive C2 implant — config crypto, OAuth tasking, command dispatch, host profiling | idasql | [OceanDrift/README.md](OceanDrift/README.md) |

## Repository Policy

- Public repo content is documentation, scripts, and non-sensitive research metadata.
- Sensitive artifacts (IDA/Ghidra databases, malware binaries, extracted drivers) are not distributed in this public repository.

## Research Use

This repository is intended for defensive security research and education.
