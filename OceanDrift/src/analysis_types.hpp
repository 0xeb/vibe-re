#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>
#include <curl/curl.h>

namespace oceandrift::analysis {

using json = nlohmann::json;

struct FunctionEvidence {
  std::uint32_t address = 0;
  std::string function;
  std::string purpose;
  std::vector<std::string> indicators;
};

struct WorkflowStep {
  int order = 0;
  std::string title;
  std::string detail;
};

// ============================================================================
//  GraphApiSession  --  Recovered from graph_api_session_create (0x4195B0)
//
//  The binary allocates 0x118 = 280 bytes via operator new.  Field layout
//  derived from sso_string_copy_construct calls and DWORD-indexed
//  initialization in the constructor, cross-referenced with offset
//  accesses in graph_api_refresh_access_token and graph_api_request_json.
//
//  MSVC 32-bit std::string (SSO) = 24 bytes:
//    union { char inline_buf[16]; char* heap_ptr; }  +0   (16 bytes)
//    size_t len                                      +16  (4 bytes)
//    size_t cap                                      +20  (4 bytes)
// ============================================================================
struct GraphApiSession {
    std::string proxy_host;       /* +0    (24 bytes) */
    int         proxy_port;       /* +24   (4 bytes)  */
    std::string proxy_user;       /* +28   (24 bytes) */
    std::string proxy_pass;       /* +52   (24 bytes) */
    std::uint8_t proxy_enabled;   /* +76   (1 byte)   */
    char        pad_77[3];        /* +77   (3 bytes alignment) */
    std::string config_param_0;   /* +80   (24 bytes) -- first ctor arg */
    std::string client_id;        /* +104  (24 bytes) */
    std::string tenant_id;        /* +128  (24 bytes) */
    std::string client_secret;    /* +152  (24 bytes) */
    std::string scope;            /* +176  (24 bytes) */
    std::string access_token;     /* +200  (24 bytes) */
    std::string refresh_token;    /* +224  (24 bytes) */
    std::int64_t token_expiry;    /* +248  (8 bytes)  */
    std::string graph_base_url;   /* +256  (24 bytes) */
    /* Total: 280 bytes (0x118) */
};

// ============================================================================
//  BeaconContext — Core state structure for the C2 beacon
//  Layout: 500 bytes total, derived from beacon_context_init (0x0040EE30)
// ============================================================================
struct BeaconContext {
    std::string client_id;         /* +0    */
    std::string client_secret;     /* +24   */
    std::string refresh_token;     /* +48   */
    std::string tenant_id;         /* +72   */
    std::string drive_root;        /* +96   */
    int         sleep_seconds;     /* +120  */
    int         field_124;         /* +124  */
    int         field_128;         /* +128  */
    void*       graph_session;     /* +132  -- pointer to GraphApiSession */
    std::string agent_id;          /* +136  */
    std::string base_path;         /* +160  */
    std::string job_path;          /* +184  */
    std::string result_path;       /* +208  */
    std::string upload_path;       /* +232  */
    std::string download_path;     /* +256  */
    uint8_t     running_flag;      /* +280  */
    uint8_t     alive_flag;        /* +281  */
    char        pad_282[2];        /* +282  alignment */
    uint32_t    thread_handle_1[2];/* +284  */
    uint32_t    thread_handle_2[2];/* +292  */
    /* +300  _Mtx_t mutex_1 (48 bytes) */
    /* +348  _Mtx_t mutex_2 (48 bytes) */
    /* +396  condition_variable (40 bytes) */
    /* +436  condition_variable (40 bytes) */
    std::string shell_output;      /* +476  */
};

// ============================================================================
//  Cross-TU function declarations
// ============================================================================

// --- runtime.cpp — utilities ---
bool        path_exists(const std::string& path);
std::uint64_t path_file_size(const std::string& path);
std::string wstring_to_multibyte(const std::wstring& wide);
std::string get_current_directory_w();
void        sleep_for_seconds(std::int64_t seconds);
std::string format_config_dat_path();
std::string format_config_json_path();
std::string u64_to_decimal_string(std::uint64_t value);

// --- runtime.cpp — JSON helpers ---
json*       json_get_object_member(json* obj, const char* key);
std::string json_get_string(json* node);
bool        json_has_member(json* obj, const char* key);
json        json_parse_string(const std::string& text);
int         json_node_to_int(json* node);

// --- runtime.cpp — config getters ---
std::string get_graphapi_client_id(json* root);
std::string get_graphapi_tenant_id(json* root);
std::string get_graphapi_client_secret(json* root);
std::string get_graphapi_redirect_uri(json* root);

// --- runtime.cpp — proxy ---
bool        clear_proxy_settings();
bool        parse_proxy_args(int argc, const char** argv);
std::string get_proxy_host();
std::string get_proxy_user();
std::string get_proxy_password();
bool        apply_proxy_settings(GraphApiSession* session,
                const std::string& host, int port,
                const std::string& user, const std::string& pass);
extern int  g_proxy_port;
extern bool g_proxy_enabled;

// --- runtime.cpp — curl wrappers ---
CURL*       curl_easy_init_wrapper();
CURLcode    curl_easy_perform_wrapper(CURL* handle);
void        curl_easy_cleanup_wrapper(CURL* handle);
CURLcode    curl_easy_getinfo_wrapper(CURL* handle, CURLINFO info, long* out);
curl_slist* curl_slist_append_wrapper(curl_slist* list, const char* s);
void        curl_slist_free_all_wrapper(curl_slist* list);

// --- runtime.cpp — misc ---
bool        token_is_expired(std::int64_t expiry_ticks);
size_t      curl_write_callback(char* ptr, size_t size, size_t nmemb, void* userdata);
bool        istring_equal(const char* s1, size_t len1, const char* s2, size_t len2);

// --- config.cpp ---
bool load_config_from_file(json* out, const std::string& path);

// --- persistence.cpp ---
bool handle_autostart_flag(int argc, const char** argv);

// --- host_profile.cpp ---
std::string build_host_profile_json();
std::string build_host_machine_guid();

// --- graph_api.cpp ---
bool      graph_api_refresh_access_token(GraphApiSession* session);
json      graph_api_request_json(
              GraphApiSession* session,
              const std::string& method,
              const std::string& body,
              const std::string& content_type,
              const std::string& request_path);

// --- beacon.cpp ---
void beacon_context_init(BeaconContext* ctx, const BeaconContext* src);
bool beacon_initialize(BeaconContext* ctx);
bool beacon_start_workers(BeaconContext* ctx);
bool beacon_is_running(BeaconContext* ctx);
void beacon_stop_workers(BeaconContext* ctx);
void beacon_context_destroy(BeaconContext* ctx);
void graph_api_config_clear(BeaconContext* ctx);

// ============================================================================

std::array<std::uint8_t, 16> decode_xor_key();
std::string decode_hex_xor_payload(std::string_view hex_payload);

std::vector<std::string> supported_commands();
std::vector<std::string> task_paths();
std::vector<std::string> oauth_token_form_fields();
std::vector<std::string> host_profile_fields();

// --- decode_hex_xor_payload.cpp ---
FunctionEvidence decode_hex_xor_evidence();
FunctionEvidence config_loader_evidence();

// --- beacon_analysis.cpp ---
FunctionEvidence command_dispatch_evidence();
FunctionEvidence worker_loop_evidence();
FunctionEvidence beacon_init_evidence();
FunctionEvidence beacon_ctx_init_evidence();
FunctionEvidence start_workers_evidence();
FunctionEvidence shell_exec_evidence();
FunctionEvidence upload_file_evidence();
FunctionEvidence publish_result_evidence();
FunctionEvidence select_task_evidence();
FunctionEvidence download_task_evidence();
FunctionEvidence spawn_detached_evidence();
FunctionEvidence escape_json_evidence();

// --- graph_analysis.cpp ---
FunctionEvidence graph_refresh_evidence();
FunctionEvidence graph_request_evidence();

// --- host_analysis.cpp ---
FunctionEvidence host_profile_evidence();
FunctionEvidence mac_address_evidence();
FunctionEvidence machine_guid_evidence();
FunctionEvidence md5_hex_evidence();
FunctionEvidence wmi_processor_evidence();

// --- startup_analysis.cpp ---
FunctionEvidence startup_autorun_evidence();

// --- main_workflow_analysis.cpp ---
FunctionEvidence main_workflow_evidence();

std::vector<WorkflowStep> main_workflow();
std::vector<FunctionEvidence> full_evidence_catalog();

}  // namespace oceandrift::analysis
