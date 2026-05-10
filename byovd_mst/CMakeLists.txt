cmake_minimum_required(VERSION 3.20)
project(mst_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# Client library (static)
add_library(mst_lib STATIC mst.c mst.h)
target_include_directories(mst_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Demo executable
add_executable(mst_demo demo.c)
target_link_libraries(mst_demo PRIVATE mst_lib)
