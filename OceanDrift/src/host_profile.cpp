// host_profile.cpp -- Cleaned IDA decompilation of the host-profiling
// subsystem from the OceanDrift implant (32-bit PE).
//
// This is a malware-analysis artefact.  The pseudocode faithfully represents
// the binary's behaviour as recovered by IDA; it is NOT functional C++.

#include "analysis_types.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

// --- Win32 / COM forward declarations (analysis stubs) ---
// These mirror the APIs the binary actually imports.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <wbemidl.h>
#include <wincrypt.h>
#include <lm.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

namespace oceandrift::analysis {

// Opaque JSON helpers -- the binary uses a lightweight JSON builder
// internally; we represent the result as std::string here.
// sub_40D920 = json_value_from_string
// sub_40CC20 = json_object_set_value
// sub_406E40 = json_serialize_to_string
// sub_4070B0 = json_value_free


// ============================================================================
//  get_os_version  (0x00404410)
// ----------------------------------------------------------------------------
//  Retrieves the Windows version by dynamically loading RtlGetVersion from
//  ntdll.dll (to bypass GetVersionEx deprecation).  Maps major.minor.build
//  to human-readable strings ("Windows 10", "Windows Server 2019", etc.).
//  Also calls GetProductInfo to distinguish workstation vs. server SKUs.
//  Returns "Unknown" on failure.
// ============================================================================
static std::string get_os_version()
{
    /* 0x404445 -- load RtlGetVersion dynamically from ntdll.dll */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return "Unknown";

    typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    auto pRtlGetVersion = reinterpret_cast<RtlGetVersionPtr>(
        GetProcAddress(ntdll, "RtlGetVersion"));

    if (!pRtlGetVersion)
        return "Unknown";

    RTL_OSVERSIONINFOW osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    if (pRtlGetVersion(&osvi) != 0)
        return "Unknown";

    DWORD major = osvi.dwMajorVersion;
    DWORD minor = osvi.dwMinorVersion;
    DWORD build = osvi.dwBuildNumber;

    /* 0x4044A0 -- GetProductInfo for SKU type */
    DWORD product_type = 0;
    GetProductInfo(major, minor, 0, 0, &product_type);

    /* 0x4044C0 -- Map version numbers to display names */
    std::string version_name;

    if (major == 10 && minor == 0)
    {
        if (build >= 22000)                                         /* Windows 11 */
            version_name = "Windows 11";
        else
            version_name = "Windows 10";

        /* Server SKU check */
        if (product_type >= 0x30)
        {
            if (build >= 20348)
                version_name = "Windows Server 2022";
            else if (build >= 17763)
                version_name = "Windows Server 2019";
            else
                version_name = "Windows Server 2016";
        }
    }
    else if (major == 6 && minor == 3)
        version_name = "Windows 8.1";
    else if (major == 6 && minor == 2)
        version_name = "Windows 8";
    else if (major == 6 && minor == 1)
        version_name = "Windows 7";
    else if (major == 6 && minor == 0)
        version_name = "Windows Vista";
    else
        version_name = "Unknown";

    /* 0x4045E0 -- Append build number */
    char build_str[32] = {};
    sprintf_s(build_str, sizeof(build_str), " (Build %lu)", build);
    version_name += build_str;

    return version_name;
}


// ============================================================================
//  get_user_name  (0x004046B0)
// ----------------------------------------------------------------------------
//  Simple wrapper around GetUserNameA.  Returns the current user's login
//  name, or "unknown" if the call fails.
// ============================================================================
static std::string get_user_name()
{
    char name_buf[256] = {};
    DWORD buf_size = 256;

    if (GetUserNameA(name_buf, &buf_size))
    {
        return std::string(name_buf, strlen(name_buf));
    }

    return "unknown";
}


// ============================================================================
//  get_workgroup  (0x00404790)
// ----------------------------------------------------------------------------
//  Retrieves the computer's domain or workgroup name.  First tries
//  GetComputerNameExA(ComputerNamePhysicalDnsDomain).  If that fails,
//  falls back to NetGetJoinInformation to get the workgroup name
//  (converting from wide to multibyte via WideCharToMultiByte).
//  Returns "WORKGROUP" if both methods produce empty results.
// ============================================================================
static std::string get_workgroup()
{
    std::string result;

    /* 0x40480D -- Try GetComputerNameExA for DNS domain first */
    char domain_buf[260] = {};
    DWORD domain_size = 260;

    if (GetComputerNameExA(ComputerNamePhysicalDnsDomain,
                           domain_buf, &domain_size))
    {
        result.assign(domain_buf, strlen(domain_buf));
    }
    else
    {
        /* 0x404853 -- Fallback: NetGetJoinInformation */
        LPWSTR name_buffer = nullptr;
        NET_API_STATUS status;
        NETSETUP_JOIN_STATUS join_status;

        status = NetGetJoinInformation(nullptr, &name_buffer,
                                       &join_status);

        if (status == NERR_Success
            && join_status == NetSetupWorkgroupName
            && name_buffer)
        {
            /* 0x404894 -- Convert wide name to multibyte */
            int narrow_len = WideCharToMultiByte(
                0xFDE9u, 0, name_buffer, -1, nullptr, 0, nullptr, nullptr);

            if (narrow_len > 0)
            {
                std::string narrow(narrow_len - 1, '\0');
                WideCharToMultiByte(0xFDE9u, 0, name_buffer, -1,
                                    &narrow[0], narrow_len,
                                    nullptr, nullptr);
                result = narrow;
            }
        }

        if (name_buffer)
            NetApiBufferFree(name_buffer);
    }

    /* 0x40497C -- Default to "WORKGROUP" if empty */
    if (result.empty())
        result = "WORKGROUP";

    return result;
}


// ============================================================================
//  get_time_zone  (0x00404C90)
// ----------------------------------------------------------------------------
//  Calls GetTimeZoneInformation and formats the result as a UTC offset
//  string in the form "UTC+HH:MM" or "UTC-HH:MM".  The Bias field is
//  negated to get the offset from UTC (positive bias = west of UTC =
//  negative offset).
//
//  Uses std::ostringstream internally with std::setw(2) and
//  std::setfill('0') for zero-padded hours and minutes.
//  Returns "Unknown" on GetTimeZoneInformation failure.
// ============================================================================
static std::string get_time_zone()
{
    TIME_ZONE_INFORMATION tzi = {};

    if (GetTimeZoneInformation(&tzi) == TIME_ZONE_ID_INVALID)
    {
        GetLastError();
        return "Unknown";
    }

    /* 0x404D14 -- Bias is in minutes; positive = west of UTC */
    LONG bias = tzi.Bias;

    /* 0x404D4F -- Sign: positive bias means UTC- */
    const char* sign = (bias > 0) ? "-" : "+";

    int abs_bias = (bias < 0) ? -bias : bias;
    int hours   = abs_bias / 60;
    int minutes = abs_bias % 60;

    /* 0x404D5C -- Format as "UTC+HH:MM" with zero-padded fields */
    std::ostringstream oss;
    oss << "UTC" << sign
        << std::setfill('0') << std::setw(2) << hours
        << ":"
        << std::setfill('0') << std::setw(2) << minutes;

    return oss.str();
}


// ============================================================================
//  wmi_get_physical_media_serial  (0x00405610)
// ----------------------------------------------------------------------------
//  Performs a WMI query "SELECT SerialNumber FROM Win32_PhysicalMedia"
//  and returns the SerialNumber field as a narrow string.  Full COM
//  lifecycle identical to wmi_get_processor_id:
//    CoInitializeEx -> CoInitializeSecurity -> CoCreateInstance(WbemLocator)
//    -> ConnectServer("ROOT\\CIMV2") -> CoSetProxyBlanket
//    -> ExecQuery(WQL) -> enumerate -> Get("SerialNumber")
//    -> cleanup / CoUninitialize
//  Returns empty string on any failure.
// ============================================================================
static std::string wmi_get_physical_media_serial()
{
    std::string result;                                             /* Block */

    /* 0x40567F -- COM init */
    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED)))
        return {};

    /* 0x405729 -- Security blanket */
    if (FAILED(CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                                     RPC_C_AUTHN_LEVEL_NONE,
                                     RPC_C_IMP_LEVEL_IMPERSONATE,
                                     nullptr, EOAC_NONE, nullptr)))
    {
        CoUninitialize();
        return {};
    }

    /* 0x4056F9 -- Create WbemLocator */
    IWbemLocator* pLocator = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr,
                                CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator,
                                reinterpret_cast<void**>(&pLocator))))
    {
        CoUninitialize();
        return {};
    }

    /* 0x405742 -- Connect to ROOT\\CIMV2 namespace */
    IWbemServices* pServices = nullptr;
    BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
    HRESULT hr = pLocator->ConnectServer(bstrNamespace,
                                          nullptr, nullptr, nullptr,
                                          0, nullptr, nullptr,
                                          &pServices);
    SysFreeString(bstrNamespace);

    if (FAILED(hr))
    {
        pLocator->Release();
        CoUninitialize();
        return {};
    }

    /* 0x4057F8 -- Set proxy security */
    if (FAILED(CoSetProxyBlanket(pServices,
                                  RPC_C_AUTHN_WINNT,
                                  RPC_C_AUTHZ_NONE, nullptr,
                                  RPC_C_AUTHN_LEVEL_CALL,
                                  RPC_C_IMP_LEVEL_IMPERSONATE,
                                  nullptr, EOAC_NONE)))
    {
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
        return {};
    }

    /* 0x40582D -- Execute the WQL query */
    IEnumWbemClassObject* pEnumerator = nullptr;
    BSTR bstrWQL   = SysAllocString(L"WQL");
    BSTR bstrQuery = SysAllocString(
        L"SELECT SerialNumber FROM Win32_PhysicalMedia");

    hr = pServices->ExecQuery(bstrWQL, bstrQuery,
                               WBEM_FLAG_FORWARD_ONLY |
                               WBEM_FLAG_RETURN_IMMEDIATELY,
                               nullptr, &pEnumerator);
    SysFreeString(bstrQuery);
    SysFreeString(bstrWQL);

    if (FAILED(hr))
    {
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
        return {};
    }

    /* 0x4059A0 -- Enumerate first result row */
    IWbemClassObject* pObj = nullptr;
    ULONG uReturn = 0;

    if (pEnumerator)
    {
        pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &uReturn);

        if (uReturn && pObj)
        {
            VARIANT vtProp;
            VariantInit(&vtProp);

            /* 0x4059D1 -- Get("SerialNumber") */
            hr = pObj->Get(L"SerialNumber", 0, &vtProp, nullptr, nullptr);
            if (SUCCEEDED(hr)
                && vtProp.vt == VT_BSTR
                && vtProp.bstrVal)
            {
                /* 0x4059FC -- Convert BSTR to narrow string */
                int wideLen = SysStringLen(vtProp.bstrVal);
                int narrowLen = WideCharToMultiByte(CP_ACP, 0,
                                    vtProp.bstrVal, wideLen,
                                    nullptr, 0, nullptr, nullptr);
                if (narrowLen > 0)
                {
                    result.resize(narrowLen);
                    WideCharToMultiByte(CP_ACP, 0,
                                        vtProp.bstrVal, wideLen,
                                        &result[0], narrowLen,
                                        nullptr, nullptr);
                }
            }

            VariantClear(&vtProp);
            pObj->Release();
        }

        pEnumerator->Release();
    }

    /* 0x405AAF -- Cleanup */
    pServices->Release();
    pLocator->Release();
    CoUninitialize();

    return result;
}


// ============================================================================
//  compute_md5_hex  (0x00404FA0)
// ----------------------------------------------------------------------------
//  Computes the MD5 digest of the input string and returns it as a 32-char
//  lowercase hex string.  Uses the Windows CryptoAPI (CALG_MD5 = 0x8003).
//  Returns empty string on any CryptoAPI failure.
// ============================================================================
static std::string compute_md5_hex(const std::string& input)
{
    HCRYPTPROV hProv  = 0;
    HCRYPTHASH hHash  = 0;
    DWORD      hashLen = 16;
    BYTE       hashBuf[16] = {};
    char       hexBuf[33]  = {};                        /* 16 bytes * 2 + NUL */

    /* 0x00404FF7  --  Acquire a CSP handle (PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) */
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr,
                               PROV_RSA_FULL, 0xF0000000))
    {
        return {};                                      /* LABEL_13 */
    }

    /* 0x00405015  --  Create an MD5 hash object */
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);                  /* LABEL_12 */
        return {};
    }

    /* 0x0040504A  --  Hash the input data */
    if (!CryptHashData(hHash,
                       reinterpret_cast<const BYTE*>(input.data()),
                       static_cast<DWORD>(input.size()), 0)
        || !CryptGetHashParam(hHash, HP_HASHVAL, hashBuf, &hashLen, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return {};
    }

    /* 0x0040505C  --  Format each byte as two lowercase hex digits */
    char* p = hexBuf;
    for (DWORD i = 0; i < hashLen; ++i)
    {
        sprintf_s(p, 3, "%02x", hashBuf[i]);           /* sub_402390 */
        p += 2;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return std::string(hexBuf, strlen(hexBuf));
}


// ============================================================================
//  get_primary_mac_address  (0x004049C0)
// ----------------------------------------------------------------------------
//  Enumerates network adapters via GetAdaptersInfo and formats the first
//  adapter's 6-byte hardware address as "XX:XX:XX:XX:XX:XX" (uppercase hex,
//  zero-padded, colon-separated).
//  Returns empty string if no adapter is found.
// ============================================================================
static std::string get_primary_mac_address()
{
    std::string result;

    ULONG bufSize = 0;
    /* 0x00404A4C  --  First call to determine required buffer size.
       ERROR_BUFFER_OVERFLOW = 111 */
    if (GetAdaptersInfo(nullptr, &bufSize) != ERROR_BUFFER_OVERFLOW)
        return result;

    IP_ADAPTER_INFO* adapters =
        static_cast<IP_ADAPTER_INFO*>(malloc(bufSize));
    if (!adapters)
        return result;

    /* 0x00404A72  --  Retrieve adapter list */
    if (GetAdaptersInfo(adapters, &bufSize) == NO_ERROR)
    {
        /* 0x00404AC3-0x00404B2E  --  Format 6 MAC bytes from first adapter */
        std::ostringstream oss;
        oss << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < 6; ++i)
        {
            oss << std::setw(2)
                << static_cast<unsigned>(adapters->Address[i]);
            if (i < 5)
                oss << ":";
        }
        result = oss.str();
    }

    free(adapters);
    return result;
}


// ============================================================================
//  wmi_get_processor_id  (0x00405110)
// ----------------------------------------------------------------------------
//  Performs a WMI query  "SELECT ProcessorId FROM Win32_Processor"  and
//  returns the ProcessorId field as a narrow string.  Full COM lifecycle:
//    CoInitializeEx  ->  CoInitializeSecurity  ->  CoCreateInstance(WbemLocator)
//    ->  ConnectServer("ROOT\\CIMV2")  ->  CoSetProxyBlanket
//    ->  ExecQuery(WQL)  ->  enumerate  ->  Get("ProcessorId")
//    ->  cleanup / CoUninitialize
// ============================================================================
static std::string wmi_get_processor_id()
{
    std::string result;                                 /* Block */

    /* 0x0040517F  --  COM init */
    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED)))
        return {};

    /* 0x00405229  --  Security blanket */
    if (FAILED(CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                                     RPC_C_AUTHN_LEVEL_NONE,
                                     RPC_C_IMP_LEVEL_IMPERSONATE,
                                     nullptr, EOAC_NONE, nullptr)))
    {
        CoUninitialize();
        return {};
    }

    /* 0x004051F9  --  Create WbemLocator */
    IWbemLocator* pLocator = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr,
                                CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator,
                                reinterpret_cast<void**>(&pLocator))))
    {
        CoUninitialize();
        return {};
    }

    /* 0x00405242  --  Connect to ROOT\\CIMV2 namespace */
    IWbemServices* pServices = nullptr;
    BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
    HRESULT hr = pLocator->ConnectServer(bstrNamespace,
                                          nullptr, nullptr, nullptr,
                                          0, nullptr, nullptr,
                                          &pServices);
    SysFreeString(bstrNamespace);

    if (FAILED(hr))
    {
        pLocator->Release();
        CoUninitialize();
        return {};
    }

    /* 0x004052F8  --  Set proxy security on the services interface */
    if (FAILED(CoSetProxyBlanket(pServices,
                                  RPC_C_AUTHN_WINNT,
                                  RPC_C_AUTHZ_NONE, nullptr,
                                  RPC_C_AUTHN_LEVEL_CALL,
                                  RPC_C_IMP_LEVEL_IMPERSONATE,
                                  nullptr, EOAC_NONE)))
    {
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
        return {};
    }

    /* 0x0040532D  --  Execute the WQL query */
    IEnumWbemClassObject* pEnumerator = nullptr;
    BSTR bstrWQL   = SysAllocString(L"WQL");
    BSTR bstrQuery = SysAllocString(
        L"SELECT ProcessorId FROM Win32_Processor");

    hr = pServices->ExecQuery(bstrWQL, bstrQuery,
                               WBEM_FLAG_FORWARD_ONLY |
                               WBEM_FLAG_RETURN_IMMEDIATELY,
                               nullptr, &pEnumerator);
    SysFreeString(bstrQuery);
    SysFreeString(bstrWQL);

    if (FAILED(hr))
    {
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
        return {};
    }

    /* 0x00405490-0x0040558D  --  Enumerate first result row */
    IWbemClassObject* pObj = nullptr;
    ULONG uReturn = 0;

    if (pEnumerator)
    {
        pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &uReturn);

        if (uReturn && pObj)
        {
            VARIANT vtProp;
            VariantInit(&vtProp);

            /* 0x004054D1  --  Get("ProcessorId") */
            hr = pObj->Get(L"ProcessorId", 0, &vtProp, nullptr, nullptr);
            if (SUCCEEDED(hr)
                && vtProp.vt == VT_BSTR
                && vtProp.bstrVal)
            {
                /* 0x004054FC  --  Convert BSTR to narrow string */
                int wideLen = SysStringLen(vtProp.bstrVal);
                int narrowLen = WideCharToMultiByte(CP_ACP, 0,
                                    vtProp.bstrVal, wideLen,
                                    nullptr, 0, nullptr, nullptr);
                if (narrowLen > 0)
                {
                    result.resize(narrowLen);
                    WideCharToMultiByte(CP_ACP, 0,
                                        vtProp.bstrVal, wideLen,
                                        &result[0], narrowLen,
                                        nullptr, nullptr);
                }
            }

            VariantClear(&vtProp);
            pObj->Release();
        }

        pEnumerator->Release();
    }

    /* 0x004055AF-0x004055BB  --  Cleanup */
    pServices->Release();
    pLocator->Release();
    CoUninitialize();

    return result;
}


// ============================================================================
//  build_host_machine_guid  (0x00405B10)
// ----------------------------------------------------------------------------
//  Constructs a GUID-like host identifier by:
//    1.  Concatenating:  MAC address  +  WMI ProcessorId  +  WMI disk serial
//    2.  Computing the MD5 hex digest (32 chars) of that concatenation.
//    3.  Splitting the 32-hex-char digest into a GUID-formatted string:
//            XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
//            [0..8)  -[8..12)-[12..16)-[16..20)-[20..32)
//  Returns empty string if the combined fingerprint is empty or the MD5
//  digest is not exactly 32 characters.
// ============================================================================
std::string build_host_machine_guid()
{
    /* 0x00405B4E  --  Collect hardware identifiers */
    std::string mac_addr   = get_primary_mac_address();           /* lhs */
    std::string cpu_id     = wmi_get_processor_id();              /* rhs */
    std::string disk_serial = wmi_get_physical_media_serial();    /* Srca */

    /* 0x00405BB1  --  Concatenate:  mac + cpu_id + disk_serial */
    std::string combined = mac_addr + cpu_id;                     /* Block */
    combined += disk_serial;
    std::string fingerprint = std::move(combined);                /* pbData */

    /* 0x00405C60  --  Early-out when there is nothing to hash */
    if (fingerprint.empty())
        return {};                                                /* byte_4D4918 */

    /* 0x00405D93  --  Hash the combined fingerprint */
    std::string md5 = compute_md5_hex(fingerprint);               /* Src */

    /* 0x00405DA0  --  Require exactly 32 hex characters */
    if (md5.size() != 32)
        return {};

    /* 0x00405E40-0x0040611A  --  Format as GUID:
       part5 = md5[20..32)  (12 chars)   -- Block / assigned first
       part4 = md5[16..20)  ( 4 chars)
       part3 = md5[12..16)  ( 4 chars)
       part2 = md5[ 8..12)  ( 4 chars)
       part1 = md5[ 0.. 8)  ( 8 chars)
       Result = part1 + "-" + part2 + "-" + part3 + "-" + part4 + "-" + part5
    */
    std::string part5 = md5.substr(20, 12);
    std::string part4 = md5.substr(16,  4);
    std::string part3 = md5.substr(12,  4);
    std::string part2 = md5.substr( 8,  4);
    std::string part1 = md5.substr( 0,  8);

    /* 0x00405FB2-0x0040611A  --  Concatenate with dashes */
    std::string guid;
    guid  = part1 + "-";
    guid += part2 + "-";
    guid += part3 + "-";
    guid += part4 + "-";
    guid += part5;

    return guid;
}


// ============================================================================
//  build_host_profile_json  (0x004039E0)
// ----------------------------------------------------------------------------
//  Gathers system information and constructs a JSON object with these fields:
//      "IP Address"        --  local IPv4 via gethostname + getaddrinfo
//      "Operating System"  --  Windows version string  (sub_404410)
//      "Host Name"         --  GetComputerNameA  (fallback "unknown")
//      "User Name"         --  GetUserNameA-equivalent  (sub_4046B0)
//      "Workgroup"         --  NetWkstaGetInfo or equivalent  (sub_404790)
//      "MAC Address"       --  get_primary_mac_address
//      "Privilege"         --  "Admin" or "Regular User" via SID check
//      "Time Zone"         --  GetTimeZoneInformation  (sub_404C90)
//
//  Returns the serialised JSON as a std::string.
// ============================================================================
std::string build_host_profile_json()
{
    // ----- 1.  Resolve local IP address via Winsock -------------------
    std::string ip_address;                                  /* v72 / v68 */

    /* 0x00403A59  --  WSAStartup(MAKEWORD(2,2)) */
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0)
    {
        char hostname[256] = {};
        /* 0x00403A73  --  gethostname */
        if (gethostname(hostname, 256) == 0)
        {
            ADDRINFOA hints = {};
            hints.ai_family   = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            PADDRINFOA addrResult = nullptr;
            /* 0x00403AD5  --  getaddrinfo */
            int gaiRet = getaddrinfo(hostname, nullptr, &hints, &addrResult);
            if (gaiRet == 0)
            {
                char ipBuf[22] = {};
                /* 0x00403B15  --  inet_ntop (AF_INET) */
                if (inet_ntop(AF_INET,
                              &reinterpret_cast<sockaddr_in*>(
                                  addrResult->ai_addr)->sin_addr,
                              ipBuf, sizeof(ipBuf)))
                {
                    ip_address.assign(ipBuf, strlen(ipBuf));
                }
                freeaddrinfo(addrResult);
            }
            else
            {
                /* 0x00403AF8  --  FormatMessageW (error path, result unused) */
            }
        }
        WSACleanup();
    }

    // ----- 2.  Collect host identity strings --------------------------

    /* 0x00403B7B  --  Operating System version */
    std::string os_version = get_os_version();               /* sub_404410 -> v59 */

    /* 0x00403BB2  --  Computer name  (fallback "unknown") */
    std::string computer_name;
    {
        char nameBuf[256] = {};
        DWORD nameSize = 256;
        if (GetComputerNameA(nameBuf, &nameSize))
        {
            nameBuf[255] = '\0';
            computer_name.assign(nameBuf, strlen(nameBuf));
        }
        else
        {
            computer_name = "unknown";
        }
    }

    /* 0x00403C1D  --  User name */
    std::string user_name = get_user_name();                 /* sub_4046B0 -> v61 */

    /* 0x00403C2C  --  Workgroup / domain */
    std::string workgroup = get_workgroup();                 /* sub_404790 -> v63 */

    /* 0x00403C3B  --  MAC address */
    std::string mac_address = get_primary_mac_address();     /* -> block */

    // ----- 3.  Determine privilege level ------------------------------
    /* 0x00403C66-0x00403CBD  --  Check for Administrators group membership
       using AllocateAndInitializeSid + CheckTokenMembership.
       SID authority = SECURITY_NT_AUTHORITY  { 0,0,0,0,0,5 }
       Sub-authorities: SECURITY_BUILTIN_DOMAIN_RID (0x20),
                        DOMAIN_ALIAS_RID_ADMINS   (0x220).       */
    std::string privilege;
    {
        BOOL isAdmin = FALSE;
        PSID adminSid = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

        if (AllocateAndInitializeSid(&ntAuth, 2,
                SECURITY_BUILTIN_DOMAIN_RID,                    /* 0x20  */
                DOMAIN_ALIAS_RID_ADMINS,                        /* 0x220 */
                0, 0, 0, 0, 0, 0,
                &adminSid))
        {
            BOOL isMember = FALSE;
            if (CheckTokenMembership(nullptr, adminSid,
                                      &isMember))
            {
                isAdmin = isMember;
            }
            FreeSid(adminSid);
        }

        if (isAdmin)
            privilege = "Admin";
        else
            privilege = "Regular User";
    }

    // ----- 4.  Time zone ----------------------------------------------
    std::string time_zone = get_time_zone();                 /* sub_404C90 -> Block */

    // ----- 5.  Build JSON object ---------------------------------------
    /* The binary uses a lightweight internal JSON library:
         json_value_init_type(&root, JSON_VALUE_OBJECT)      -- 0x00403D2E
         json_value_from_string(value, &string)              -- sub_40D920
         json_object_set_value(root, "key", value)           -- sub_40CC20
         json_serialize_to_string(root, &out)                -- sub_406E40
         json_value_free(root)                               -- sub_4070B0        */

    // json_set(root, "IP Address",       ip_address)
    // json_set(root, "Operating System", os_version)
    // json_set(root, "Host Name",        computer_name)
    // json_set(root, "User Name",        user_name)
    // json_set(root, "Workgroup",        workgroup)
    // json_set(root, "MAC Address",      mac_address)
    // json_set(root, "Privilege",        privilege)
    // json_set(root, "Time Zone",        time_zone)

    /* 0x0040419F  --  json_serialize_to_string -> sub_406E40 */
    /* For analysis purposes we represent this as manual JSON construction: */
    std::string json;
    json  = "{";
    json += "\"IP Address\":\""       + ip_address     + "\",";
    json += "\"Operating System\":\"" + os_version     + "\",";
    json += "\"Host Name\":\""        + computer_name  + "\",";
    json += "\"User Name\":\""        + user_name      + "\",";
    json += "\"Workgroup\":\""        + workgroup      + "\",";
    json += "\"MAC Address\":\""      + mac_address    + "\",";
    json += "\"Privilege\":\""        + privilege       + "\",";
    json += "\"Time Zone\":\""        + time_zone      + "\"";
    json += "}";

    return json;
}


// ============================================================================
//  Public API  --  field list & evidence (unchanged contract)
// ============================================================================

std::vector<std::string> host_profile_fields() {
    return {
        "IP Address",
        "Operating System",
        "Host Name",
        "User Name",
        "Workgroup",
        "MAC Address",
        "Privilege",
        "Time Zone",
    };
}

FunctionEvidence host_profile_evidence() {
    FunctionEvidence out;
    out.address  = 0x004039E0;
    out.function = "build_host_profile_json";
    out.purpose  = "Builds host identity/profile JSON used for beacon "
                   "registration and status";
    out.indicators = {
        "WSAStartup(0x202) + gethostname + getaddrinfo + inet_ntop "
            "for local IP",
        "GetComputerNameA (fallback \"unknown\")",
        "AllocateAndInitializeSid(NT_AUTHORITY, BUILTIN_ADMINS) + "
            "CheckTokenMembership -> \"Admin\" / \"Regular User\"",
        "JSON keys: IP Address, Operating System, Host Name, User Name, "
            "Workgroup, MAC Address, Privilege, Time Zone",
    };
    return out;
}

FunctionEvidence mac_address_evidence() {
    FunctionEvidence out;
    out.address  = 0x004049C0;
    out.function = "get_primary_mac_address";
    out.purpose  = "Retrieves first network adapter MAC via GetAdaptersInfo "
                   "and formats as XX:XX:XX:XX:XX:XX";
    out.indicators = {
        "GetAdaptersInfo(nullptr, &size) == ERROR_BUFFER_OVERFLOW",
        "malloc(size) + GetAdaptersInfo",
        "6-byte Address[] formatted with std::setw(2) + ':' separator",
    };
    return out;
}

FunctionEvidence machine_guid_evidence() {
    FunctionEvidence out;
    out.address  = 0x00405B10;
    out.function = "build_host_machine_guid";
    out.purpose  = "Constructs a GUID-like host identifier from "
                   "MD5(MAC + ProcessorId + DiskSerial)";
    out.indicators = {
        "Concatenates: mac_address + processor_id + disk_serial",
        "compute_md5_hex of combined string",
        "Splits 32-char MD5 hex into GUID format: "
            "8-4-4-4-12",
        "Returns empty string when fingerprint is empty or MD5 != 32 chars",
    };
    return out;
}

FunctionEvidence md5_hex_evidence() {
    FunctionEvidence out;
    out.address  = 0x00404FA0;
    out.function = "compute_md5_hex";
    out.purpose  = "Computes MD5 digest via CryptoAPI and returns lowercase "
                   "32-char hex string";
    out.indicators = {
        "CryptAcquireContextW(PROV_RSA_FULL, 0xF0000000)",
        "CryptCreateHash(CALG_MD5 = 0x8003)",
        "CryptHashData + CryptGetHashParam(HP_HASHVAL)",
        "sprintf \"%02x\" per byte",
    };
    return out;
}

FunctionEvidence wmi_processor_evidence() {
    FunctionEvidence out;
    out.address  = 0x00405110;
    out.function = "wmi_get_processor_id";
    out.purpose  = "Queries WMI for CPU identifier string";
    out.indicators = {
        "CoInitializeEx + CoInitializeSecurity",
        "CoCreateInstance(CLSID_WbemLocator)",
        "ConnectServer(\"ROOT\\\\CIMV2\")",
        "ExecQuery: \"SELECT ProcessorId FROM Win32_Processor\"",
        "Get(L\"ProcessorId\") on first enumerated object",
    };
    return out;
}

}  // namespace oceandrift::analysis
