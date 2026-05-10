cmake_minimum_required(VERSION 3.20)
project(immunetutildriver_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# Client library (static)
add_library(immunetutildriver_lib STATIC immunetutildriver.c immunetutildriver.h)
target_include_directories(immunetutildriver_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Demo executable
add_executable(immunetutildriver_demo demo.c)
target_link_libraries(immunetutildriver_demo PRIVATE immunetutildriver_lib)
