cmake_minimum_required(VERSION 2.8)

project(cpp-socks)

add_definitions(-Wall)
add_definitions(-Wextra)
add_definitions(-g)
add_definitions(-std=c++11)

include_directories(include)

add_subdirectory(src)
