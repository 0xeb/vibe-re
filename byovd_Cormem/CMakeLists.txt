cmake_minimum_required(VERSION 3.20)
project(cormem_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# Client library (static)
add_library(cormem_lib STATIC cormem.c cormem.h)
target_include_directories(cormem_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Demo executable
add_executable(cormem_demo demo.c)
target_link_libraries(cormem_demo PRIVATE cormem_lib)
