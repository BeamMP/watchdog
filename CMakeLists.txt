cmake_minimum_required(VERSION 3.0)

if(WIN32)
    project(watchdog CXX)
endif()

set(CMAKE_CXX_STANDARD 17)
add_library(watchdog STATIC watchdog.cpp watchdog.h)

if(WIN32)
    target_link_libraries(watchdog Dbghelp)
endif()