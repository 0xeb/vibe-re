cmake_minimum_required(VERSION 3.20)

if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
      CACHE STRING "Vcpkg toolchain file")
endif()

project(oceandrift_analysis LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(IDASQL_HOST "127.0.0.1" CACHE STRING "IDASQL host")
set(IDASQL_PORT "8188" CACHE STRING "IDASQL HTTP port")

# --- External dependencies via vcpkg ---
find_package(CURL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_library(oceandrift_analysis STATIC
  config.cpp
  persistence.cpp
  graph_api.cpp
  beacon.cpp
  host_profile.cpp
  main.cpp
  runtime.cpp
  catalog.cpp
  project_anchor.cpp
)

target_include_directories(oceandrift_analysis
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(oceandrift_analysis
  PRIVATE
    CURL::libcurl
    nlohmann_json::nlohmann_json
)

if(MSVC)
  target_compile_options(oceandrift_analysis PRIVATE /W4)
else()
  target_compile_options(oceandrift_analysis PRIVATE -Wall -Wextra -Wpedantic)
endif()

find_program(POWERSHELL_EXE NAMES pwsh powershell REQUIRED)

add_custom_target(refresh_manifest
  COMMAND "${POWERSHELL_EXE}" -NoProfile -ExecutionPolicy Bypass
          -File "${CMAKE_CURRENT_SOURCE_DIR}/scripts/refresh_manifest_from_idasql.ps1"
          -ServerHost "${IDASQL_HOST}"
          -Port "${IDASQL_PORT}"
          -OutputCsv "${CMAKE_CURRENT_SOURCE_DIR}/manifest/functions.csv"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  COMMENT "Refreshing function manifest from IDASQL (${IDASQL_HOST}:${IDASQL_PORT})"
  VERBATIM
)
