# ============================================================================
# PROCEXP152.sys — Kernel driver
# Build requires WDK 10+
# ============================================================================

add_library(procexp152 SHARED
    procexp.c
)

set_target_properties(procexp152 PROPERTIES
    OUTPUT_NAME "PROCEXP152"
    SUFFIX      ".sys"
    PREFIX      ""
)

target_include_directories(procexp152 PRIVATE
    "${WDK_INC}/km"
    "${WDK_INC}/km/crt"
    "${WDK_INC}/shared"
    "${CMAKE_SOURCE_DIR}/common"
)

target_compile_definitions(procexp152 PRIVATE
    _AMD64_
    _WIN64
    _KERNEL_MODE
    POOL_NX_OPTIN=1
    NTDDI_VERSION=0x0A000000
    _WIN32_WINNT=0x0A00
)

target_compile_options(procexp152 PRIVATE
    /kernel
    /GS
    /W4
    /Gz
    /Zp8
)

target_link_directories(procexp152 PRIVATE
    "${WDK_LIB}/km/x64"
)

target_link_libraries(procexp152 PRIVATE
    ntoskrnl.lib
    hal.lib
    wdmsec.lib
)

target_link_options(procexp152 PRIVATE
    /DRIVER
    /SUBSYSTEM:NATIVE
    /ENTRY:DriverEntry
    /NODEFAULTLIB
    /MANIFEST:NO
    /MERGE:.rdata=.text
    /SECTION:.text,ERP
    /INTEGRITYCHECK
)
