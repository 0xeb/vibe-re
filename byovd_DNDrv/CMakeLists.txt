cmake_minimum_required(VERSION 3.20)
project(dndrv_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# Client library (static)
add_library(dndrv_lib STATIC dndrv.c dndrv.h)
target_include_directories(dndrv_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Demo executable
add_executable(dndrv_demo demo.c)
target_link_libraries(dndrv_demo PRIVATE dndrv_lib)
