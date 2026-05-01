# ============================================================================
# procexp_client — User-mode CLI for exercising the PROCEXP152 driver
# ============================================================================

add_executable(procexp_client
    main.c
    drvclient.c
)

target_include_directories(procexp_client PRIVATE
    "${CMAKE_SOURCE_DIR}/common"
)

target_compile_definitions(procexp_client PRIVATE
    _AMD64_
    _WIN64
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(procexp_client PRIVATE
    advapi32
    ntdll
)

set_target_properties(procexp_client PROPERTIES
    OUTPUT_NAME "procexp_client"
)
