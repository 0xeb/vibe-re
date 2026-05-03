// runtime.cpp — Cleaned decompilations of runtime helper functions
// referenced throughout the OceanDrift implant.
//
// The binary statically links libcurl and bundles nlohmann::json v3.11.3.
// Implementations below are faithful to the IDA decompilations with SSO
// string internals and scope-guard bookkeeping stripped for readability.
//
// This is a malware-analysis artefact, NOT functional code.

#include "analysis_types.hpp"

#include <nlohmann/json.hpp>
#include <curl/curl.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
using DWORD   = unsigned long;
using LPWSTR  = wchar_t*;
using LPCWSTR = const wchar_t*;
using HANDLE  = void*;
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#define INVALID_HANDLE_VALUE ((HANDLE)(long long)-1)
inline DWORD GetFileAttributesW(LPCWSTR) { return INVALID_FILE_ATTRIBUTES; }
inline DWORD GetCurrentDirectoryW(DWORD, LPWSTR) { return 0; }
inline int MultiByteToWideChar(unsigned, DWORD, const char*, int, wchar_t*, int) { return 0; }
inline int WideCharToMultiByte(unsigned, DWORD, const wchar_t*, int, char*, int, const char*, int*) { return 0; }
inline HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE) { return INVALID_HANDLE_VALUE; }
inline int GetFileSizeEx(HANDLE, void*) { return 0; }
inline int CloseHandle(HANDLE) { return 0; }
inline void Sleep(DWORD) {}
#endif

namespace oceandrift::analysis {

using json = nlohmann::json;

// ============================================================================
//  path_exists
//
//  Converts the narrow path to wide via MultiByteToWideChar(CP_UTF8),
//  then calls GetFileAttributesW.  Returns true if the result is not
//  INVALID_FILE_ATTRIBUTES.
// ============================================================================
bool path_exists(const std::string& path)
{
#ifdef _WIN32
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wide_len <= 0) return false;
    std::wstring wide(wide_len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wide.data(), wide_len);
    DWORD attrs = GetFileAttributesW(wide.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES;
#else
    (void)path;
    return false;
#endif
}

// ============================================================================
//  path_file_size
//
//  Opens the file with CreateFileW(GENERIC_READ), calls GetFileSizeEx
//  to retrieve the 64-bit file size, then CloseHandle.  Returns 0 on
//  failure.
// ============================================================================
std::uint64_t path_file_size(const std::string& path)
{
#ifdef _WIN32
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wide_len <= 0) return 0;
    std::wstring wide(wide_len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wide.data(), wide_len);

    HANDLE hFile = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(hFile, &size)) {
        CloseHandle(hFile);
        return 0;
    }
    CloseHandle(hFile);
    return static_cast<std::uint64_t>(size.QuadPart);
#else
    (void)path;
    return 0;
#endif
}

// ============================================================================
//  wstring_to_multibyte
//
//  Converts a wide string (UTF-16) to a narrow (multibyte) string using
//  WideCharToMultiByte with code page CP_UTF8.
// ============================================================================
std::string wstring_to_multibyte(const std::wstring& wide)
{
#ifdef _WIN32
    if (wide.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
                                  nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string result(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
                        result.data(), len, nullptr, nullptr);
    return result;
#else
    (void)wide;
    return {};
#endif
}

// ============================================================================
//  get_current_directory_w
//
//  Calls GetCurrentDirectoryW to retrieve the working directory as a
//  wide string, then converts to narrow via wstring_to_multibyte.
// ============================================================================
std::string get_current_directory_w()
{
#ifdef _WIN32
    wchar_t buf[MAX_PATH + 1]{};
    DWORD len = GetCurrentDirectoryW(MAX_PATH + 1, buf);
    if (len == 0) return {};
    return wstring_to_multibyte(std::wstring(buf, len));
#else
    return {};
#endif
}

// ============================================================================
//  sleep_for_seconds
//
//  Sleeps for the specified number of seconds.  Internally calls
//  _Xtime_get_ticks + _Thrd_sleep (MSVC CRT threading primitives).
// ============================================================================
void sleep_for_seconds(std::int64_t seconds)
{
    if (seconds > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(seconds));
    }
}

// ============================================================================
//  format_config_dat_path / format_config_json_path
//
//  Return the literal config filenames.
// ============================================================================
std::string format_config_dat_path()
{
    return "config.dat";
}

std::string format_config_json_path()
{
    return "config.json";
}

// ============================================================================
//  u64_to_decimal_string
//
//  Converts a uint64_t to its decimal string representation.  The binary
//  implements this with a manual digit-extraction loop using constant
//  division by 10 and 1000000000.
// ============================================================================
std::string u64_to_decimal_string(std::uint64_t value)
{
    return std::to_string(value);
}

// ============================================================================
//  JSON helpers — the binary bundles nlohmann::json v3.11.3
//
//  The original code uses nlohmann::json's internal tree structure with
//  SSO string keys.  These wrappers provide the same interface used
//  throughout the decompiled code.
// ============================================================================

// json_get_object_member: Looks up a member by key in a JSON object.
// Returns a pointer to the member's value node, or a static null JSON
// if the key is absent.  The binary throws nlohmann::json::type_error
// (code 305) if 'this' is not an object.
json* json_get_object_member(json* obj, const char* key)
{
    static json null_val;
    if (!obj || !obj->is_object()) return &null_val;
    auto it = obj->find(key);
    if (it == obj->end()) return &null_val;
    return &(*it);
}

// json_get_string: Extracts the string value from a JSON string node.
// Throws nlohmann::json::type_error (code 302) if node is not a string.
std::string json_get_string(json* node)
{
    if (!node || !node->is_string()) return {};
    return node->get<std::string>();
}

// json_has_member: Returns true if the JSON object contains the key.
// Walks the internal red-black tree of the json object map.
bool json_has_member(json* obj, const char* key)
{
    if (!obj || !obj->is_object()) return false;
    return obj->contains(key);
}

// json_parse: Parses a raw string buffer into a JSON value tree.
json json_parse_string(const std::string& text)
{
    return json::parse(text, nullptr, false);
}

// json_node_to_int: Converts a JSON numeric value to an integer.
// Handles types 4 (bool), 5/6 (signed/unsigned int), 7 (float).
// Throws type_error 302 for non-numeric types.
int json_node_to_int(json* node)
{
    if (!node) return 0;
    if (node->is_number()) return node->get<int>();
    if (node->is_boolean()) return node->get<bool>() ? 1 : 0;
    return 0;
}

// ============================================================================
//  Config getters — extract Graph API credentials from loaded JSON
//
//  Each reads GraphAPI.<key> from the config root.  If the key is
//  missing, returns an empty string (the caller falls back to its
//  hardcoded default).
//
//  All four follow the same decompiled pattern:
//    1. json_get_object_member(root, "GraphAPI")
//    2. json_has_member(graphapi_obj, "<key>")
//    3. If found: json_get_object_member(graphapi, "<key>") → json_get_string
//    4. Else: return empty string
// ============================================================================

std::string get_graphapi_field(json* root, const char* field)
{
    json* graphapi = json_get_object_member(root, "GraphAPI");
    if (!json_has_member(graphapi, field)) return {};
    json* val = json_get_object_member(graphapi, field);
    return json_get_string(val);
}

std::string get_graphapi_client_id(json* root)
{
    return get_graphapi_field(root, "clientId");
}

std::string get_graphapi_tenant_id(json* root)
{
    return get_graphapi_field(root, "tenantId");
}

std::string get_graphapi_client_secret(json* root)
{
    return get_graphapi_field(root, "clientSecret");
}

std::string get_graphapi_redirect_uri(json* root)
{
    return get_graphapi_field(root, "redirectUri");
}

// ============================================================================
//  Proxy configuration — module-level global state
//
//  The implant supports HTTP proxy configuration via command-line arguments.
// ============================================================================
static std::string g_proxy_host;
int         g_proxy_port = 0;
static std::string g_proxy_user;
static std::string g_proxy_password;
bool        g_proxy_enabled = false;

// clear_proxy_settings: Resets all proxy globals to empty/zero.
bool clear_proxy_settings()
{
    g_proxy_host.clear();
    g_proxy_port = 0;
    g_proxy_user.clear();
    g_proxy_password.clear();
    g_proxy_enabled = false;
    return true;
}

// parse_host_port: Splits "host:port" into separate host string and port int.
// Returns true on success.
static bool parse_host_port(const std::string& spec, std::string& host_out, int& port_out)
{
    auto colon = spec.rfind(':');
    if (colon == std::string::npos) return false;
    host_out = spec.substr(0, colon);
    port_out = std::atoi(spec.substr(colon + 1).c_str());
    return port_out > 0;
}

// parse_proxy_args: Scans argv for:
//   --proxy <host:port>   --user <user>   --pass <password>
// Populates module-level proxy globals.  Falls back to 127.0.0.1:8080
// if --proxy is specified without a value.
// Returns true if --proxy was found and parsed successfully.
bool parse_proxy_args(int argc, const char** argv)
{
    std::string proxy_spec;
    std::string proxy_user_arg;
    std::string proxy_pass_arg;
    bool proxy_seen = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--proxy") == 0) {
            proxy_seen = true;
            if (i + 1 < argc) {
                proxy_spec = argv[++i];
            } else {
                proxy_spec = "127.0.0.1:8080";
            }
        } else if (std::strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            proxy_user_arg = argv[++i];
        } else if (std::strcmp(argv[i], "--pass") == 0 && i + 1 < argc) {
            proxy_pass_arg = argv[++i];
        }
    }

    if (!proxy_seen) return false;

    std::string parsed_host;
    int parsed_port = 0;
    if (!parse_host_port(proxy_spec, parsed_host, parsed_port))
        return false;

    g_proxy_host     = parsed_host;
    g_proxy_port     = parsed_port;
    g_proxy_user     = proxy_user_arg;
    g_proxy_password = proxy_pass_arg;
    g_proxy_enabled  = true;
    return true;
}

// Proxy getters — return the current proxy config if enabled, else empty.
std::string get_proxy_host()
{
    return g_proxy_enabled ? g_proxy_host : std::string{};
}

std::string get_proxy_user()
{
    return g_proxy_enabled ? g_proxy_user : std::string{};
}

std::string get_proxy_password()
{
    return g_proxy_enabled ? g_proxy_password : std::string{};
}

// apply_proxy_settings: Copies proxy config into a GraphApiSession struct.
//   session->proxy_host    = host
//   session->proxy_port    = port
//   session->proxy_user    = user
//   session->proxy_pass    = pass
//   session->proxy_enabled = (host.length() > 0)
bool apply_proxy_settings(GraphApiSession* session,
                                 const std::string& host, int port,
                                 const std::string& user, const std::string& pass)
{
    session->proxy_host    = host;
    session->proxy_port    = port;
    session->proxy_user    = user;
    session->proxy_pass    = pass;
    session->proxy_enabled = !host.empty();
    return session->proxy_enabled;
}

// ============================================================================
//  curl wrappers — thin forwarding stubs around libcurl
//
//  The binary links libcurl statically.  These wrappers add thread-safe
//  initialization (SRWLock + curl_global_init) before the first call.
// ============================================================================

// curl_easy_init_wrapper: Acquires an SRW lock, ensures curl_global_init
// has been called (flags 3 = CURL_GLOBAL_ALL), then returns curl_easy_init().
CURL* curl_easy_init_wrapper()
{
    static bool initialized = false;
    if (!initialized) {
        curl_global_init(CURL_GLOBAL_ALL);
        initialized = true;
    }
    return curl_easy_init();
}

// curl_easy_perform_wrapper: Calls curl_easy_perform, returns CURLcode.
CURLcode curl_easy_perform_wrapper(CURL* handle)
{
    return curl_easy_perform(handle);
}

// curl_easy_cleanup_wrapper: Calls curl_easy_cleanup to free the handle.
void curl_easy_cleanup_wrapper(CURL* handle)
{
    curl_easy_cleanup(handle);
}

// curl_easy_getinfo_wrapper: Calls curl_easy_getinfo to retrieve info.
CURLcode curl_easy_getinfo_wrapper(CURL* handle, CURLINFO info, long* out)
{
    return curl_easy_getinfo(handle, info, out);
}

// curl_slist_append_wrapper: Appends a string to a curl_slist.
curl_slist* curl_slist_append_wrapper(curl_slist* list, const char* s)
{
    return curl_slist_append(list, s);
}

// curl_slist_free_all_wrapper: Frees an entire curl_slist linked list.
void curl_slist_free_all_wrapper(curl_slist* list)
{
    curl_slist_free_all(list);
}

// ============================================================================
//  token_is_expired — compares a stored token-expiry timepoint against
//  _Xtime_get_ticks() (100ns ticks since epoch).  Returns true if the
//  current time is past the expiry.
// ============================================================================
bool token_is_expired(std::int64_t expiry_ticks)
{
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto ticks = std::chrono::duration_cast<std::chrono::duration<int64_t, std::ratio<1, 10000000>>>(now).count();
    return ticks >= expiry_ticks;
}

// ============================================================================
//  curl_write_callback — libcurl WRITEFUNCTION callback.  Appends received
//  data to the std::string* passed as the userdata pointer.
// ============================================================================
size_t curl_write_callback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    size_t total = size * nmemb;
    auto* output = static_cast<std::string*>(userdata);
    output->append(ptr, total);
    return total;
}

// ============================================================================
//  istring_equal — case-insensitive string comparison.
//  Returns true when the two strings match (ignoring case).
// ============================================================================
bool istring_equal(const char* s1, size_t len1, const char* s2, size_t len2)
{
    if (len1 != len2) return false;
    for (size_t i = 0; i < len1; ++i) {
        if (std::tolower(static_cast<unsigned char>(s1[i])) !=
            std::tolower(static_cast<unsigned char>(s2[i])))
            return false;
    }
    return true;
}

}  // namespace oceandrift::analysis
