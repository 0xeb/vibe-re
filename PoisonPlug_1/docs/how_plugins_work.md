# How Plugins Work

## Purpose and Scope

This is the canonical plugin anatomy reference for this repository.

It explains:

- what structure is shared across `blob_0` through `blob_7`
- what `CMD 100`, `CMD 1`, and `CMD 104` mean in practice
- how plugins get loaded, registered, and dispatched at runtime

Use this page as the entry point for plugin internals, then drill into per-blob docs for module-specific behavior.

## Plugin Lifecycle at a Glance

```text
inner worker thread
  -> decrypt blob (IMUL)
  -> decompress blob (LZ77)
  -> reflective-load plugin PE
  -> CMD 100 (inject parent framework context)
  -> CMD 1   (plugin initializes and populates callbacks/vtable)
  -> CMD 104 (return plugin vtable pointer)
  -> register plugin entry in linked list
  -> orchestrator/router dispatches work through that vtable
```

The registration handshake `100 -> 1 -> 104` is the stable core path used to make a plugin callable.

## Common Plugin Skeleton

At a high level, each plugin behaves like a command dispatcher:

```c
BOOL DllMain_dispatcher(HINSTANCE hinst, DWORD fdwReason, LPVOID lpReserved) {
  switch (fdwReason) {
    case 100: /* receive parent ctx / framework vtable */ break;
    case 1:   /* initialize plugin state + populate plugin vtable */ break;
    case 104: /* return &plugin_vtable */ break;
    /* optional metadata/cleanup commands */
  }
  return TRUE;
}
```

What stays invariant:

- command-dispatch style entrypoint
- parent context injection
- callback/vtable exposure
- framework-side registration into a plugin list

What varies:

- vtable shape (transport vs online vs utility)
- plugin-specific domain logic (install, config, recon, transport, registry)

## Command Protocol Semantics

### Core registration commands

| Command | Direction | Meaning |
|---------|-----------|---------|
| `100` | Framework -> Plugin | Provide parent framework context/vtable pointer. Plugin caches this for later service calls. |
| `1` | Framework -> Plugin | Plugin initialization. Populates plugin-owned callback table/vtable and internal state. |
| `104` | Framework -> Plugin | Request plugin vtable pointer so framework can register and invoke it. |

### Auxiliary commands

Commands for cleanup, version, and name queries are also present, but exact numeric mapping can vary by module/build notes in this corpus. The registration-critical behavior is consistently centered on `100`, `1`, and `104`.

## What "Framework Context" Means

`CMD 100` is effectively dependency injection for plugin services.

After storing the parent context pointer, a plugin can call shared framework capabilities such as:

- memory helpers (`alloc`, `free`)
- crypto/compression helpers (IMUL/LZ-related packet helpers)
- API resolution helpers
- blob loading / reflective loading helpers
- object/list management helpers

This is why modules like `blob_2` can run with zero static imports: parent-provided services cover core runtime needs.

## How Plugins Get Dispatched and Execute

A plugin becomes executable only after registration finishes:

1. Blob is loaded and handshake runs (`100 -> 1 -> 104`)
2. Framework stores returned vtable pointer in plugin registry/list
3. Orchestrator and routing code find target plugins and call their callbacks through that vtable

Execution opportunities then come from:

- startup bootstrap flow (worker thread registration sequence)
- command routing flow (incoming C2 command dispatch path)
- plugin-internal loops/threads after initialization

## Shared Structure Across `blob_0` to `blob_7`

Shared:

- dispatcher-centric entrypoint
- same high-level registration handshake
- encrypted strings and dynamic/runtime-oriented service usage
- framework-mediated registration and invocation

Role-specific differences:

- `blob_0` / `blob_1` / `blob_2`: utility behaviors
- `blob_3`: routing/orchestration behavior
- `blob_4` to `blob_7`: transport protocol implementations

## Vtable Families

| Family | Typical Slots | Used By | Purpose |
|--------|---------------|---------|---------|
| Transport vtable | 6 | TCP/HTTP/UDP/DNS plugins | Uniform channel operations (`open`, `close`, `read`, `write`, dispatch, loop) |
| Online vtable | 14 | `blob_3` | C2 routing, channel lifecycle, stream/pipeline helpers |
| Utility/simple vtables | 2-5 | Install/Plugins/Config | Focused module-specific operations |

## Quick Blob Mapping

| Blob | Friendly Name | Role | Vtable Family | Deep Dive |
|------|---------------|------|---------------|-----------|
| `blob_0` | Install | Process launcher + anti-analysis | Utility/simple | [blob_0_install_analysis.md](blob_0_install_analysis.md) |
| `blob_1` | Plugins | Registry persistence | Utility/simple | [blob_1_plugins_analysis.md](blob_1_plugins_analysis.md) |
| `blob_2` | Config | Config/file operations | Utility/simple | [blob_2_config_analysis.md](blob_2_config_analysis.md) |
| `blob_3` | Online | Recon + C2 routing | Online (extended) | [blob_3_online_analysis.md](blob_3_online_analysis.md) |
| `blob_4` | TCP | TCP transport | Transport | [blob_4_tcp_analysis.md](blob_4_tcp_analysis.md) |
| `blob_5` | HTTP | HTTP transport | Transport | [blob_5_http_analysis.md](blob_5_http_analysis.md) |
| `blob_6` | UDP | UDP transport | Transport | [blob_6_udp_analysis.md](blob_6_udp_analysis.md) |
| `blob_7` | DNS | DNS transport | Transport | [blob_7_dns_analysis.md](blob_7_dns_analysis.md) |

## Evidence and Further Reading

- Framework internals and loader behavior: [inner_pe_analysis.md](inner_pe_analysis.md)
- Plugin catalog and architecture snapshot: [blob_index.md](blob_index.md)
- Long-form end-to-end narrative: [scatterbrain_analysis.md](scatterbrain_analysis.md)
- Full execution path context: [execution_walkthrough.md](execution_walkthrough.md)
