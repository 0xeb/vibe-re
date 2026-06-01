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

### BYOVD Driver Client Libraries

Client libraries and demos for 10 vulnerable signed Windows kernel drivers (BYOVD).
Each project includes typed IOCTL wrappers and a demo program — no WDK required to build.
Driver binaries were previously available from KeServiceDescriptorTable/vulnerable-drivers (see [RELATED.md](RELATED.md)).

All BYOVD analysis was performed using [ghidrasql](https://github.com/0xeb/ghidrasql) and [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (Opus 4.6, 1M context).

| Project | Driver | Key Capabilities |
|---------|--------|-----------------|
| [byovd_DNDrv](byovd_DNDrv/) | DNDrv.sys (VBoxDrv) | Ring-0 code loading, kernel page mapping, VM execution, 30+ IOCTLs |
| [byovd_GGProtect64](byovd_GGProtect64/) | GGProtect64.sys | 60+ IOCTLs: DLL injection, SSDT introspection, I/O ports, callback stripping |
| [byovd_KmWpsMs](byovd_KmWpsMs/) | KmWpsMs.sys (NcHost) | Arbitrary physical memory R/W, VA-to-PA translation, MDL mapping |
| [byovd_Cormem](byovd_Cormem/) | Cormem.sys (Sapera LT) | Physical memory mapping, I/O ports, DMA allocation, scatter-gather |
| [byovd_mst](byovd_mst/) | mst.sys (Mellanox/NVIDIA) | PCI config R/W, physical memory mapping, HCA reset, firmware commands |
| [byovd_gibepext](byovd_gibepext/) | gibepext.sys (Group-IB) | Physical memory R/W, PCI config, MSR read, IO-space mapping |
| [byovd_SysFile_X64](byovd_SysFile_X64/) | SysFile_X64.sys | MSR R/W, I/O ports, PCI config, physical memory — zero validation |
| [byovd_fastdumpx64](byovd_fastdumpx64/) | fastdumpx64.sys (CounterTack) | Physical memory dump, MSR read, CPUID, MTRR, ELF64 crash dumps |
| [byovd_ImmunetUtilDriver](byovd_ImmunetUtilDriver/) | ImmunetUtilDriver.sys (Cisco) | Kernel object introspection, cross-process handle theft, namespace enum |
| [byovd_bin_intigua_driver64](byovd_bin_intigua_driver64/) | bin_intigua_driver64.sys | IAT hooking of services.exe, shellcode injection, PPL bypass |

## Repository Policy

- Public repo content is documentation, scripts, and non-sensitive research metadata.
- Sensitive artifacts (IDA/Ghidra databases, malware binaries, extracted drivers) are not distributed in this public repository.

## Related Work

See [RELATED.md](RELATED.md) for related reverse-engineering and security research projects.

## License

This repository is licensed under the [BSD 3-Clause License](LICENSE).

## Disclaimer

This repository contains materials produced through independent security
research, including reverse-engineered source reconstructions, analysis
scripts, technical reports, and client libraries for vulnerable kernel
drivers. All materials are provided exclusively for **defensive security
research, education, and vulnerability analysis**.

**No malware distribution.** This repository does not contain malware
binaries, exploit payloads, or vulnerable driver binaries. Source
reconstructions document vulnerabilities — they do not enable attacks.
Driver binaries referenced in BYOVD projects must be obtained from their
respective public sources.

**No warranty.** All materials are provided "as is" without warranty of
any kind. See [LICENSE](LICENSE) for the full warranty disclaimer.

**No liability.** The authors assume no liability for any use or misuse
of the materials in this repository. Users are solely responsible for
ensuring their use complies with applicable laws and regulations.

**Responsible use.** Users of this repository are expected to:

- Use materials for defensive research, education, or authorized security testing only
- Not use materials for unauthorized access to systems or data
- Not redistribute sensitive artifacts obtained through private access channels
- Follow responsible disclosure practices
- Comply with all applicable laws in their jurisdiction

**Reconstructed source code.** Source code in this repository is
reconstructed from reverse engineering of publicly available binaries.
These reconstructions are original works of authorship and do not imply
ownership of, or rights to, the original binaries or their intellectual
property.

**Third-party references.** References to vendor names, driver names,
malware family names, and threat actor attributions are used for
identification purposes in a research context and do not imply
affiliation with or endorsement by any referenced party.
