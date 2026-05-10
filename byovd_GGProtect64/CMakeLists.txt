cmake_minimum_required(VERSION 3.20)
project(ggprotect64_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# Client library (static)
add_library(ggprotect64_lib STATIC ggprotect64.c ggprotect64.h)
target_include_directories(ggprotect64_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Demo executable
add_executable(ggprotect64_demo demo.c)
target_link_libraries(ggprotect64_demo PRIVATE ggprotect64_lib)
