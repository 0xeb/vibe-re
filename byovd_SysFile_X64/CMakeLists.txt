cmake_minimum_required(VERSION 3.20)
project(winhwdriver_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# Client library (static)
add_library(winhwdriver_lib STATIC winhwdriver.c winhwdriver.h)
target_include_directories(winhwdriver_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Demo executable
add_executable(winhwdriver_demo demo.c)
target_link_libraries(winhwdriver_demo PRIVATE winhwdriver_lib)
