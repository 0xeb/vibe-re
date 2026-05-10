cmake_minimum_required(VERSION 3.20)
project(intigua_driver_client LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# Client library (static)
add_library(intigua_driver_lib STATIC intigua_driver.c intigua_driver.h)
target_include_directories(intigua_driver_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Demo executable
add_executable(intigua_driver_demo demo.c)
target_link_libraries(intigua_driver_demo PRIVATE intigua_driver_lib)
