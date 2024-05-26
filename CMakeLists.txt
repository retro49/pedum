cmake_minimum_required(VERSION 3.28.2)
project("i_peparser")
set(CMAKE_CXX_FLAGS "-Wall -Wno-dev -ggdb3")
set(CMAKE_C_FLAGS "-Wall -Wno-dev -ggdb3")

add_library(i_stream
    STATIC
    i_types.h
    i_stream.h
    i_stream.c)

add_library(i_peparser
    STATIC
    i_peparser.c
    i_types.h
)

target_link_libraries(i_peparser PUBLIC i_stream)
add_executable(dumpit dumpit.c)

target_link_libraries(dumpit PUBLIC i_stream)
target_link_libraries(dumpit PUBLIC i_peparser)
