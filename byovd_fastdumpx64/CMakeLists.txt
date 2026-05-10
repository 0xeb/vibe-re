cmake_minimum_required(VERSION 3.20)
project(fastdump_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# Client library (static)
add_library(fastdump_lib STATIC fastdump.c fastdump.h)
target_include_directories(fastdump_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Demo executable
add_executable(fastdump_demo demo.c)
target_link_libraries(fastdump_demo PRIVATE fastdump_lib)
