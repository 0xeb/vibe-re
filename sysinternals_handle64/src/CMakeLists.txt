# ============================================================================
# PROCEXP152 — Driver + Client top-level build
#
# Build client only (no WDK required):
#   cmake -B build -G "Visual Studio 17 2022"
#   cmake --build build --config Release --target procexp_client
#
# Build driver + client (requires WDK 10):
#   cmake -B build -G "Visual Studio 17 2022" -DBUILD_DRIVER=ON \
#         -DWDK_ROOT="C:/Program Files (x86)/Windows Kits/10"
#   cmake --build build --config Release
#
# Layout:
#   common/     Shared header (IOCTL codes, structures)
#   driver/     Kernel driver (PROCEXP152.sys)
#   client/     User-mode CLI (procexp_client.exe)
# ============================================================================

cmake_minimum_required(VERSION 3.16)
project(procexp152_suite C)

option(BUILD_DRIVER "Build the kernel driver (requires WDK)" OFF)

# --- Always build the client ---
add_subdirectory(client)

# --- Optionally build the driver ---
if(BUILD_DRIVER)
    # Locate WDK
    if(NOT DEFINED WDK_ROOT)
        foreach(_kit_root
            "C:/Program Files (x86)/Windows Kits/10"
            "C:/Program Files/Windows Kits/10"
            "$ENV{WDKContentRoot}")
            if(IS_DIRECTORY "${_kit_root}/Include")
                set(WDK_ROOT "${_kit_root}")
                break()
            endif()
        endforeach()
    endif()

    if(NOT WDK_ROOT)
        message(FATAL_ERROR
            "WDK not found. Set -DWDK_ROOT=<path>, e.g.:\n"
            "  cmake -B build -DBUILD_DRIVER=ON "
            "-DWDK_ROOT=\"C:/Program Files (x86)/Windows Kits/10\"")
    endif()

    message(STATUS "WDK_ROOT: ${WDK_ROOT}")

    # Find the latest version
    file(GLOB _wdk_versions LIST_DIRECTORIES true "${WDK_ROOT}/Include/*")
    list(SORT _wdk_versions)
    list(GET _wdk_versions -1 _wdk_inc_dir)
    get_filename_component(WDK_VERSION "${_wdk_inc_dir}" NAME)
    message(STATUS "WDK version: ${WDK_VERSION}")

    set(WDK_INC "${WDK_ROOT}/Include/${WDK_VERSION}" CACHE STRING "")
    set(WDK_LIB "${WDK_ROOT}/Lib/${WDK_VERSION}" CACHE STRING "")

    add_subdirectory(driver)
endif()
