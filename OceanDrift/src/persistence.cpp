#include "analysis_types.hpp"

#include <cstring>
#include <string>
#include <vector>

// Windows API forward declarations for documentation purposes
// (these mirror what the binary imports)
#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <shobjidl.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#else
// Stubs so the file is parseable on non-Windows analysis hosts
using HKEY    = void*;
using LSTATUS = long;
using BYTE    = unsigned char;
using LPCSTR  = const char*;
#define HKEY_CURRENT_USER ((HKEY)(uintptr_t)0x80000001)
#define KEY_SET_VALUE     0x0002
#define KEY_QUERY_VALUE   0x0001
#define REG_SZ            1
#define MAX_PATH          260
#endif

namespace oceandrift::analysis {

// ============================================================================
//  extract_registry_value_name  (0x004014A0)
// ----------------------------------------------------------------------------
//  Retrieves the current executable's filename (without extension) for use
//  as the registry value name under HKCU\...\Run.  Steps:
//    1. GetModuleFileNameA(nullptr, buf, 0x104) to get the full path
//    2. Scans backwards for the last path separator ('\\')
//    3. Takes everything after the separator as the filename
//    4. Scans for the last '.' to strip the extension
//    5. If the '.' appears after the last separator, truncates at the dot
//  Returns the bare filename (e.g. "oceandrift" from "C:\path\oceandrift.exe")
// ============================================================================
static void extract_registry_value_name(std::string& out)
{
    char module_path[MAX_PATH];                                     /* stack ebp-114h */

    /* 0x4014DB -- GetModuleFileNameA(nullptr, buf, 0x104) */
    DWORD path_len = GetModuleFileNameA(nullptr, module_path, 0x104u);

    if (path_len == 0)
    {
        GetLastError();
        out.assign("", 0);
        return;
    }

    /* 0x401542 -- extract the full path as a string */
    std::string full_path(module_path, strlen(module_path));

    /* 0x4015A0 -- scan backwards for last path separator '\\' */
    size_t sep_pos = full_path.rfind('\\');

    std::string filename;
    if (sep_pos != std::string::npos)
    {
        /* Take everything after the separator */
        filename = full_path.substr(sep_pos + 1);
    }
    else
    {
        filename = full_path;
    }

    /* 0x401660 -- scan for last '.' to strip extension */
    size_t dot_pos = filename.rfind('.');

    if (dot_pos != std::string::npos && dot_pos > 0)
    {
        /* Truncate at the dot (strip extension) */
        filename = filename.substr(0, dot_pos);
    }

    out = filename;
}


// ============================================================================
//  create_startup_shortcut  (0x00401750)
// ----------------------------------------------------------------------------
//  Fallback persistence method when the HKCU Run key write fails.
//  Creates a .lnk shortcut in the user's Startup folder using the
//  COM IShellLink interface.
//
//  Steps:
//    1. CoInitialize(nullptr)
//    2. SHGetFolderPathA(nullptr, CSIDL_STARTUP, ...) to get the
//       Startup folder (e.g. C:\Users\X\AppData\...\Startup)
//    3. CoCreateInstance(CLSID_ShellLink, IID_IShellLinkA)
//    4. IShellLinkA::SetPath(exe_path)
//    5. IShellLinkA::SetWorkingDirectory(exe_directory)
//    6. QueryInterface for IPersistFile
//    7. IPersistFile::Save(startup_folder + "\\" + value_name + ".lnk")
//    8. Release all COM objects and CoUninitialize
//
//  Returns non-zero on success, 0 on failure.
// ============================================================================
static int create_startup_shortcut(const std::string& value_name,
                                   const std::string& exe_path)
{
    if (value_name.empty() || exe_path.empty())
        return 0;

    /* 0x4017B0 -- CoInitialize(nullptr) */
    HRESULT hr = CoInitialize(nullptr);
    if (FAILED(hr))
        return 0;

    /* 0x4017C0 -- Get Startup folder path */
    char startup_path[MAX_PATH] = {};
    hr = SHGetFolderPathA(nullptr, 0x0007 /* CSIDL_STARTUP */,
                          nullptr, 0, startup_path);
    if (FAILED(hr))
    {
        CoUninitialize();
        return 0;
    }

    /* 0x401810 -- CoCreateInstance(CLSID_ShellLink, IID_IShellLinkA) */
    IShellLinkA* pShellLink = nullptr;
    hr = CoCreateInstance(CLSID_ShellLink, nullptr,
                          CLSCTX_INPROC_SERVER,
                          IID_IShellLinkA,
                          reinterpret_cast<void**>(&pShellLink));
    if (FAILED(hr))
    {
        CoUninitialize();
        return 0;
    }

    /* 0x401850 -- Set the target path */
    pShellLink->SetPath(exe_path.c_str());

    /* 0x401870 -- Extract directory from exe_path for SetWorkingDirectory */
    std::string exe_dir;
    size_t last_sep = exe_path.rfind('\\');
    if (last_sep != std::string::npos)
        exe_dir = exe_path.substr(0, last_sep);
    else
        exe_dir = ".";

    pShellLink->SetWorkingDirectory(exe_dir.c_str());

    /* 0x4018A0 -- QueryInterface for IPersistFile */
    IPersistFile* pPersistFile = nullptr;
    hr = pShellLink->QueryInterface(IID_IPersistFile,
                                     reinterpret_cast<void**>(&pPersistFile));
    if (FAILED(hr))
    {
        pShellLink->Release();
        CoUninitialize();
        return 0;
    }

    /* 0x4018E0 -- Build shortcut path: startup_folder\value_name.lnk */
    std::string lnk_path = std::string(startup_path) + "\\"
                          + value_name + ".lnk";

    /* 0x401930 -- Convert to wide char and save */
    wchar_t wide_lnk[MAX_PATH] = {};
    MultiByteToWideChar(CP_ACP, 0, lnk_path.c_str(), -1,
                        wide_lnk, MAX_PATH);

    hr = pPersistFile->Save(wide_lnk, TRUE);

    /* 0x401970 -- Cleanup */
    pPersistFile->Release();
    pShellLink->Release();
    CoUninitialize();

    return SUCCEEDED(hr) ? 1 : 0;
}

// ============================================================================
// IDA Decompilation  --  handle_autostart_flag  @  0x00401220
//
// Summary (malware analysis):
//   Scans argv for the "--autostart" flag.  When found, retrieves the
//   running executable's path via GetModuleFileNameA, then writes it
//   into the HKCU Run key so the malware is launched every time the
//   current user logs in.  If the registry write fails (e.g. policy or
//   access denied), it falls back to an alternative persistence method
//   via create_startup_shortcut (unresolved -- likely Startup-folder shortcut or
//   scheduled-task creation).
//
//   extract_registry_value_name(out_string)  --  populates `valueName` with the registry
//                               value name the malware uses (its
//                               persistence identifier).
//   create_startup_shortcut(valueName, exePath)  --  fallback persistence when the
//                                      registry approach fails.
// ============================================================================

/*
 * Cleaned pseudocode -- faithfully represents binary logic.
 * IDA artifacts (SSO internals, scope-guard slots, heap-free blocks)
 * have been replaced with std::string equivalents.
 */

bool handle_autostart_flag(int argc, const char** argv)
{
    int i = 1;

    if (argc <= 1)
        return false;

    /* Scan argv for "--autostart" */
    while (true)
    {
        int cmp = strcmp(argv[i], "--autostart");
        if (cmp)
            cmp = (cmp < 0) ? -1 : 1;
        if (cmp == 0)
            break;
        if (++i >= argc)
            return false;
    }

    /* Obtain the value name this malware uses in the Run key */
    std::string valueName;
    extract_registry_value_name(/*out*/ valueName);

    /* Get current executable path */
    char Filename[MAX_PATH];                                      /* stack ebp-114h */
    std::string exePath;

    if (GetModuleFileNameA(nullptr, Filename, 0x104u))
    {
        exePath.assign(Filename, strlen(Filename));
    }
    else
    {
        GetLastError();
        exePath.assign("", 0);
    }

    bool success;                                                 /* v7 / bl */

    if (exePath.size() != 0)
    {
        /* Try to open HKCU\..\Run with KEY_SET_VALUE|KEY_QUERY_VALUE (0x20006) */
        HKEY phkResult;
        LSTATUS openStatus = RegOpenKeyExA(
            HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            0,
            0x20006u,  /* KEY_SET_VALUE | KEY_QUERY_VALUE */
            &phkResult);

        if (openStatus != 0)
        {
            /* Registry open failed -- use fallback persistence */
            success = (create_startup_shortcut(valueName, exePath) != 0);
        }
        else
        {
            /* Write the exe path as a REG_SZ value */
            LSTATUS setStatus = RegSetValueExA(
                phkResult,
                valueName.c_str(),
                0,
                REG_SZ,         /* type = 1 */
                (const BYTE*)exePath.c_str(),
                (DWORD)(exePath.size() + 1));

            RegCloseKey(phkResult);

            if (setStatus != 0)
            {
                /* Registry set failed -- use fallback persistence */
                success = (create_startup_shortcut(valueName, exePath) != 0);
            }
            else
            {
                success = true;
            }
        }
    }
    else
    {
        success = false;
    }

    return success;
}

// ============================================================================
// Evidence summary for the analysis catalog
// ============================================================================

FunctionEvidence startup_autorun_evidence() {
    FunctionEvidence out;
    out.address  = 0x00401220;
    out.function = "handle_autostart_flag";
    out.purpose  = "Parses argv for --autostart; writes current exe path into "
                   "HKCU Run key for user-level persistence, with fallback via create_startup_shortcut";
    out.indicators = {
        "strcmp(argv[i], \"--autostart\")",
        "GetModuleFileNameA(nullptr, Filename, 0x104)",
        "RegOpenKeyExA(HKEY_CURRENT_USER, "
            "\"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\", 0, 0x20006, ...)",
        "RegSetValueExA(phkResult, valueName, 0, REG_SZ, exePath, len+1)",
        "RegCloseKey(phkResult)",
        "Fallback: create_startup_shortcut(valueName, exePath) on registry failure",
        "extract_registry_value_name -- retrieves persistence value name",
    };
    return out;
}

}  // namespace oceandrift::analysis
