/*
 * YARA Rules — OceanDrift Graph API C2 Implant
 *
 * Generated from static analysis of a 32-bit Windows PE binary that uses
 * Microsoft Graph API / OneDrive as its C2 transport.
 *
 * Rule set:
 *   1. oceandrift_binary        — detects the PE implant itself
 *   2. oceandrift_config_encr   — detects ENCR:-prefixed encrypted config files
 *   3. oceandrift_config_plain  — detects plaintext JSON config files
 *   4. oceandrift_xor_key       — detects any file containing the static XOR key
 *   5. oceandrift_memory        — broad memory/process scan for runtime indicators
 *
 * Usage:
 *   yara oceandrift.yar <target_path>          — scan files
 *   yara -s oceandrift.yar <target_path>       — scan with string matches shown
 *   yara oceandrift.yar -p 16 C:\             — scan entire C: drive (16 threads)
 *
 * For process memory scanning (requires admin):
 *   yara oceandrift.yar --scan-proc           — all running processes (if supported)
 */

rule oceandrift_binary
{
    meta:
        description = "OceanDrift Graph API C2 implant — PE binary detection"
        author      = "Analysis team"
        date        = "2026-02-26"
        reference   = "Static analysis of 32-bit PE using OneDrive as dead-drop C2"
        filetype    = "pe"
        sha256      = "f918849b5404c84103d9eff2f2b8e75e97724fc47f7f10078aed01d27ab8de54"
        family      = "Graphite"
        actor       = "APT28"

    strings:
        // ---- Azure AD / OAuth2 credentials (hardcoded defaults) ----
        $cred_client_id     = "675b5280-b233-4368-ba9e-b4c55cbeebe9" ascii wide
        $cred_tenant_id     = "e2aa8d24-85a2-41e6-b993-572b35980557" ascii wide
        $cred_client_secret = "gVd8Q~r5QwHkIb3NsNraqGLUPwlhnngrpYcSKbjl" ascii wide

        // ---- XOR decryption key (16 bytes at 0x4D6C44) ----
        $xor_key = { 8A 4B 2C D3 F1 E5 7A 9B 3D 6F 1C 8E 5B 2A D7 C9 }

        // ---- Graph API / OAuth2 URL fragments ----
        $url_login      = "https://login.microsoftonline.com/" ascii
        $url_graph      = "https://graph.microsoft.com/v1.0" ascii
        $url_token_path = "/oauth2/v2.0/token" ascii

        // ---- OAuth2 POST body fragments ----
        $oauth_grant    = "&grant_type=refresh_token" ascii
        $oauth_scope    = "offline_access Files.Read Files.ReadWrite" ascii

        // ---- OneDrive C2 tasking paths ----
        $drive_root     = "/me/drive/root" ascii
        $drive_items    = "/me/drive/items/" ascii
        $drive_content  = ":/content" ascii
        $drive_upload   = ":/createUploadSession" ascii

        // ---- Command dispatcher verbs (unique combination) ----
        $cmd_kill     = "kill" ascii
        $cmd_shell    = "shell" ascii
        $cmd_exec     = "exec" ascii
        $cmd_upload   = "upload" ascii
        $cmd_download = "download" ascii
        $cmd_sleep    = "sleep" ascii
        $cmd_rest     = "rest" ascii

        // ---- Implant-specific error/status strings ----
        $err_unknown    = "Unknown command: " ascii
        $err_missing    = "Missing required parameters: onedrive_path and/or agent_path" ascii
        $err_download   = "Download parameter must be a string file path" ascii
        $err_exec_fail  = "Command execution failed" ascii
        $status_inprog  = "inprogress" ascii

        // ---- Filesystem artifacts ----
        $file_beacon_out = "beacon_shell_output.txt" ascii
        $file_write_test = "test_write_permission.tmp" ascii
        $file_config_dat = "config.dat" ascii
        $file_config_json = "config.json" ascii
        $file_alive      = "alive.txt" ascii
        $file_info       = "info.txt" ascii

        // ---- Config schema keys ----
        $cfg_graphapi    = "GraphAPI" ascii
        $cfg_refreshtok  = "refreshToken" ascii

        // ---- Persistence ----
        $reg_run_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $autostart   = "--autostart" ascii

        // ---- Proxy support ----
        $proxy_flag  = "--proxy" ascii

        // ---- Host profiling strings ----
        $profile_ip   = "IP Address" ascii
        $profile_mac  = "MAC Address" ascii
        $profile_priv = "Regular User" ascii

        // ---- WMI fingerprinting queries ----
        $wmi_cpu  = "SELECT ProcessorId FROM Win32_Processor" ascii wide
        $wmi_disk = "SELECT SerialNumber FROM Win32_PhysicalMedia" ascii wide

        // ---- Agent logging strings ----
        $log_starting   = "Agent starting, working directory: " ascii
        $log_no_config  = "No configuration file found in current directory" ascii
        $log_no_refresh = "Refresh token not found in config file" ascii

    condition:
        // Must be a PE file
        uint16(0) == 0x5A4D and

        (
            // HIGH confidence: any hardcoded credential or the XOR key
            any of ($cred_*) or
            $xor_key or

            // HIGH confidence: unique error string combinations
            ($err_missing and $err_download) or
            ($err_unknown and $err_exec_fail) or

            // MEDIUM confidence: Graph API C2 pattern + tasking artifacts
            (2 of ($url_*) and 2 of ($drive_*) and $oauth_grant) or

            // MEDIUM confidence: beacon file artifacts + config schema
            ($file_beacon_out and $cfg_graphapi and $cfg_refreshtok) or

            // MEDIUM confidence: command set + OneDrive paths
            (5 of ($cmd_*) and 2 of ($drive_*)) or

            // MEDIUM confidence: agent logging strings
            (2 of ($log_*)) or

            // BROAD: WMI fingerprinting + Graph + persistence
            (1 of ($wmi_*) and 1 of ($url_*) and $reg_run_key)
        )
}


rule oceandrift_config_encrypted
{
    meta:
        description = "OceanDrift encrypted configuration file (ENCR: prefix + hex-encoded XOR payload)"
        author      = "Analysis team"
        date        = "2026-02-26"
        filetype    = "data"

    strings:
        $encr_prefix = "ENCR:" ascii

    condition:
        // File starts with ENCR: and the rest is hex characters (spot-check)
        $encr_prefix at 0 and
        filesize < 1MB and
        filesize > 10 and
        // After "ENCR:" (5 bytes), bytes should be ASCII hex [0-9A-Fa-f]
        // Check a few positions to confirm hex encoding pattern
        (uint8(5) >= 0x30 and uint8(5) <= 0x39 or    // 0-9
         uint8(5) >= 0x41 and uint8(5) <= 0x46 or    // A-F
         uint8(5) >= 0x61 and uint8(5) <= 0x66) and  // a-f
        (uint8(6) >= 0x30 and uint8(6) <= 0x39 or
         uint8(6) >= 0x41 and uint8(6) <= 0x46 or
         uint8(6) >= 0x61 and uint8(6) <= 0x66)
}


rule oceandrift_config_plaintext
{
    meta:
        description = "OceanDrift plaintext JSON configuration file"
        author      = "Analysis team"
        date        = "2026-02-26"
        filetype    = "json"

    strings:
        $graphapi     = "\"GraphAPI\"" ascii nocase
        $refreshtoken = "\"refreshToken\"" ascii
        $client_id    = "\"client_id\"" ascii nocase
        $tenant_id    = "\"tenant_id\"" ascii nocase
        $client_secret = "\"client_secret\"" ascii nocase
        $redirect_uri  = "\"redirect_uri\"" ascii nocase

        // Known attacker credentials (if reused across deployments)
        $known_client  = "675b5280-b233-4368-ba9e-b4c55cbeebe9" ascii
        $known_tenant  = "e2aa8d24-85a2-41e6-b993-572b35980557" ascii

    condition:
        filesize < 1MB and
        (
            // Config with known credentials
            any of ($known_*) or
            // GraphAPI + refreshToken is the required schema
            ($graphapi and $refreshtoken) or
            // GraphAPI key + multiple credential fields
            ($graphapi and 3 of ($client_*, $tenant_*, $redirect_uri))
        )
}


rule oceandrift_xor_key_in_file
{
    meta:
        description = "OceanDrift static 16-byte XOR decryption key (byte_4D6C44)"
        author      = "Analysis team"
        date        = "2026-02-26"

    strings:
        $xor_key = { 8A 4B 2C D3 F1 E5 7A 9B 3D 6F 1C 8E 5B 2A D7 C9 }

    condition:
        $xor_key
}


rule oceandrift_memory
{
    meta:
        description = "OceanDrift runtime indicators — for process memory scanning"
        author      = "Analysis team"
        date        = "2026-02-26"
        note        = "Use with --scan-proc or memory dump scanning"

    strings:
        // Credentials that would be in memory during operation
        $cred1 = "675b5280-b233-4368-ba9e-b4c55cbeebe9" ascii wide
        $cred2 = "e2aa8d24-85a2-41e6-b993-572b35980557" ascii wide
        $cred3 = "gVd8Q~r5QwHkIb3NsNraqGLUPwlhnngrpYcSKbjl" ascii wide

        // OAuth tokens in memory
        $bearer = "Authorization: Bearer " ascii

        // Graph API paths in memory
        $drive1 = "/me/drive/root/children" ascii
        $drive2 = "/me/drive/root:/" ascii
        $drive3 = "/me/drive/items/" ascii

        // Implant-unique strings
        $beacon_out = "beacon_shell_output.txt" ascii
        $err1       = "Missing required parameters: onedrive_path and/or agent_path" ascii
        $err2       = "Download parameter must be a string file path" ascii
        $log1       = "Agent starting, working directory: " ascii
        $log2       = "Refresh token not found in config file" ascii
        $scope      = "offline_access Files.Read Files.ReadWrite" ascii

        // XOR key in mapped image
        $xor_key = { 8A 4B 2C D3 F1 E5 7A 9B 3D 6F 1C 8E 5B 2A D7 C9 }

    condition:
        // Any credential
        any of ($cred*) or
        // XOR key
        $xor_key or
        // Unique implant strings
        any of ($err*) or
        any of ($log*) or
        // Graph C2 pattern in memory
        ($bearer and 2 of ($drive*) and $scope)
}
