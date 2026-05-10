cmake_minimum_required(VERSION 3.20)
project(nchost_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# Client library (static)
add_library(nchost_lib STATIC nchost.c nchost.h)
target_include_directories(nchost_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Demo executable
add_executable(nchost_demo demo.c)
target_link_libraries(nchost_demo PRIVATE nchost_lib)
