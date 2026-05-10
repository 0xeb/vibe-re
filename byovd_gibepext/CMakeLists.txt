cmake_minimum_required(VERSION 3.20)
project(gibepext_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# Client library (static)
add_library(gibepext_lib STATIC gibepext.c gibepext.h)
target_include_directories(gibepext_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Demo executable
add_executable(gibepext_demo demo.c)
target_link_libraries(gibepext_demo PRIVATE gibepext_lib)
