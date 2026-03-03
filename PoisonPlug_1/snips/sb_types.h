/*
 * sb_types.h -- ScatterBrain shared type definitions
 *
 * Common types used across all ScatterBrain plugin modules and the
 * inner PE loader. This header provides the cross-module structures
 * that the plugins and framework share.
 *
 * NOTE: This is recovered source for analysis purposes only.
 * It compiles as a shared library target but is NOT intended to run.
 */

#ifndef SB_TYPES_H
#define SB_TYPES_H

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <iphlpapi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------- */
typedef struct sb_framework_vtable_t sb_framework_vtable_t;
typedef struct sb_plugin_vtable_t sb_plugin_vtable_t;
typedef struct sb_plugin_entry_t sb_plugin_entry_t;
typedef struct sb_synced_list_t sb_synced_list_t;
typedef struct sb_wstr_t sb_wstr_t;
typedef struct sb_channel_t sb_channel_t;

/* ----------------------------------------------------------------
 * DllMain command protocol (fdwReason values)
 *
 * The inner PE communicates with plugins via DllMain_dispatcher
 * using extended fdwReason values. lpReserved carries the payload.
 * ---------------------------------------------------------------- */
#define SB_CMD_INIT_VTABLE 1         /* Write plugin's vtable to globals */
#define SB_CMD_SET_FRAMEWORK_CTX 100 /* lpReserved = framework vtable ptr */
#define SB_CMD_GET_NAME 103          /* Copy plugin name string to lpReserved */
#define SB_CMD_GET_VERSION 102       /* *(DWORD*)lpReserved = version int */
#define SB_CMD_GET_VTABLE_PTR 104    /* *(QWORD*)lpReserved = &vtable */

/* ----------------------------------------------------------------
 * Framework vtable (inner PE -> plugin)
 *
 * 29-entry table at inner PE's 0x18001C1B0. Passed to plugins via
 * SB_CMD_SET_FRAMEWORK_CTX. Plugins store this pointer and call
 * framework functions through it.
 *
 * Each slot is a function pointer (__int64 sized on x64).
 * ---------------------------------------------------------------- */
typedef __int64(__fastcall *sb_func_ptr_t)();

struct sb_framework_vtable_t {
  __int64 status;              /* +0x00: State/status field */
  sb_func_ptr_t plugin_loader; /* +0x08: Plugin PE detection + registration */
  sb_func_ptr_t create_obj_b;  /* +0x10: Object creator */
  sb_func_ptr_t create_obj_c;  /* +0x18: Object creator (cmd 103) */
  sb_func_ptr_t create_obj_d;  /* +0x20: Object creator */
  sb_func_ptr_t create_obj_e;  /* +0x28: Object creator */
  sb_func_ptr_t extract_filename; /* +0x30: Extract filename from path */
  sb_func_ptr_t create_obj_g;     /* +0x38: Object creator (no args) */
  sb_func_ptr_t create_obj_h;     /* +0x40: Object creator (no args) */
  sb_func_ptr_t small_alloc_i;    /* +0x48: Small allocator */
  sb_func_ptr_t small_alloc_j;    /* +0x50: Small allocator */
  sb_func_ptr_t compose_k;        /* +0x58: Composition wrapper */
  sb_func_ptr_t resolve_api;      /* +0x60: API resolver (hash + DLL) */
  sb_func_ptr_t register_blob;    /* +0x68: Blob registration wrapper */
  sb_func_ptr_t
      decrypt_and_load_blob; /* +0x70: IMUL decrypt + LZ77 decompress */
  sb_func_ptr_t
      exec_reflective_loader; /* +0x78: Copy loader to RWX, call with blob */
  sb_func_ptr_t thunk_multi_resolve; /* +0x80: Thunk to multi_resolve */
  sb_func_ptr_t multi_resolve;   /* +0x88: Multi-API resolver (largest func) */
  sb_func_ptr_t thunk_shellcode; /* +0x90: Thunk to shellcode trampoline */
  sb_func_ptr_t
      shellcode_trampoline;         /* +0x98: Shellcode execution trampoline */
  sb_func_ptr_t alloc;              /* +0xA0: Memory allocator (LocalAlloc) */
  sb_func_ptr_t compress_encrypt;   /* +0xA8: LZ77 + IMUL cipher encrypt */
  sb_func_ptr_t decrypt_decompress; /* +0xB0: IMUL cipher + LZ77 decompress */
  sb_func_ptr_t
      decrypt_packet_header;         /* +0xB8: Decrypt 20-byte packet header */
  sb_func_ptr_t free;                /* +0xC0: Memory free (LocalFree) */
  sb_func_ptr_t generate_packet_key; /* +0xC8: QPC + GetSystemTime packet key */
  sb_func_ptr_t base62_encode;       /* +0xD0: Base62 encoding utility */
  void *payload_ptr;  /* +0xD8: Payload context from outer loader */
  void *rdata_config; /* +0xE0: Pointer to encrypted config data */
};

/* ----------------------------------------------------------------
 * Plugin vtable (plugin -> inner PE)
 *
 * Each plugin exposes a vtable of function pointers that the
 * framework calls to drive plugin behavior. The transport plugins
 * (TCP, HTTP, UDP, DNS) share a common 6-entry vtable layout.
 * The Online plugin has a 14-entry vtable. Install has 2.
 * ---------------------------------------------------------------- */

/* Transport plugin vtable (TCP=200, HTTP=201, UDP=202, DNS=203) */
typedef struct sb_transport_vtable_t {
  sb_func_ptr_t dispatch_handler; /* +0x00: Command dispatch (cmd1) */
  sb_func_ptr_t main_loop;        /* +0x08: Main polling loop */
  sb_func_ptr_t open_channel;     /* +0x10: Open communication channel */
  sb_func_ptr_t close_channel;    /* +0x18: Close channel + cleanup */
  sb_func_ptr_t read_channel;     /* +0x20: Read data from channel */
  sb_func_ptr_t write_channel;    /* +0x28: Write data to channel */
} sb_transport_vtable_t;

/* Online (C2 router) plugin vtable (14 entries) */
typedef struct sb_online_vtable_t {
  sb_func_ptr_t dispatch_handler;   /* +0x00 */
  sb_func_ptr_t main_loop;          /* +0x08 */
  sb_func_ptr_t open_channel;       /* +0x10 */
  sb_func_ptr_t channel_close;      /* +0x18 */
  sb_func_ptr_t channel_read;       /* +0x20 */
  sb_func_ptr_t stream_read_loop;   /* +0x28 */
  sb_func_ptr_t thunk_unknown;      /* +0x30 */
  sb_func_ptr_t channel_write;      /* +0x38 */
  sb_func_ptr_t stream_write;       /* +0x40 */
  sb_func_ptr_t process_command;    /* +0x48 */
  sb_func_ptr_t bidirectional_pipe; /* +0x50 */
  sb_func_ptr_t channel_cancel;     /* +0x58 */
  sb_func_ptr_t check_and_release;  /* +0x60 */
  sb_func_ptr_t get_channel_type;   /* +0x68 */
} sb_online_vtable_t;

/* ----------------------------------------------------------------
 * Plugin entry (from inner PE's linked list)
 * ---------------------------------------------------------------- */
struct sb_plugin_entry_t {
  DWORD version; /* Plugin version (e.g., 200 for TCP) */
  DWORD pad;
  void *vtable;    /* Pointer to plugin's vtable */
  sb_wstr_t *name; /* Plugin name (wide string) */
  void *next;      /* Next entry in linked list */
};

/* ----------------------------------------------------------------
 * Synced list (inner PE linked list with lock)
 * ---------------------------------------------------------------- */
struct sb_synced_list_t {
  CRITICAL_SECTION lock;
  sb_plugin_entry_t *head;
  DWORD count;
};

/* ----------------------------------------------------------------
 * Wide string wrapper
 * ---------------------------------------------------------------- */
struct sb_wstr_t {
  WCHAR *buf;     /* Pointer to wide string data */
  DWORD len;      /* Length in characters */
  DWORD capacity; /* Allocated capacity */
};

/* ----------------------------------------------------------------
 * Channel context (per-connection state for transport plugins)
 * ---------------------------------------------------------------- */
struct sb_channel_t {
  void *transport_ctx;           /* +0x00: Transport-specific context */
  sb_func_ptr_t *transport_vtbl; /* +0x08: Transport vtable pointer */
  __int64 channel_data;          /* +0x10: Channel-specific data */
  WORD protocol_id;              /* +0x18: Protocol identifier (200-203) */
  WORD pad[3];
};

/* ----------------------------------------------------------------
 * Encrypted string blob header
 *
 * Each encrypted string is stored as a blob with a 2-byte key seed
 * followed by encrypted wide-char data. Decrypted via polynomial
 * XOR cipher using the key seed.
 * ---------------------------------------------------------------- */
typedef struct sb_enc_string_t {
  WORD key_seed;    /* Polynomial XOR cipher key seed */
  BYTE encrypted[]; /* Variable-length encrypted data */
} sb_enc_string_t;

/* ----------------------------------------------------------------
 * Packet header (20 bytes, IMUL-cipher encrypted)
 *
 * Used by all transport protocols for C2 communication.
 * ---------------------------------------------------------------- */
#pragma pack(push, 1)
typedef struct sb_packet_hdr_t {
  DWORD magic;        /* Packet magic / session ID */
  DWORD sequence;     /* Sequence number */
  DWORD payload_size; /* Size of following payload */
  DWORD checksum;     /* Payload checksum */
  DWORD flags;        /* Packet flags */
} sb_packet_hdr_t;
#pragma pack(pop)

/* ----------------------------------------------------------------
 * Helper function prototypes (shared across all plugins)
 *
 * These are resolved dynamically at runtime via decrypt_string()
 * and the framework's API resolution mechanism. Declared here so
 * the recovered source compiles.
 * ---------------------------------------------------------------- */

/* Framework-provided functions (from framework vtable or IAT) */
__int64 heap_alloc(size_t size);
void heap_free(void *ptr);
__int64 decrypt_string(__int64 out_buf, void *enc_blob);
void free_decrypted_string(__int64 str);
__int64 decrypt_and_resolve(__int64 dec_str, int flags);
__int64 resolve_api_by_name(__int64 resolved);
__int64 resolve_api_by_name_ws2(__int64 resolved);
__int64 peb_resolve_api_hash(DWORD hash);
void wstr_copy(sb_wstr_t *dst, const WCHAR *src);
void wstr_concat(sb_wstr_t *dst, const WCHAR *src);
void wstr_init_empty(sb_wstr_t *str);
__int64 sbstr_from_utf8(sb_wstr_t *out, const char *utf8);
void sbstr_free(sb_wstr_t *str);
char *wide_to_ansi(const WCHAR *wide);
WCHAR *utf8_to_wide(const char *utf8);
__int64 checksum_memory(const void *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* SB_TYPES_H */
