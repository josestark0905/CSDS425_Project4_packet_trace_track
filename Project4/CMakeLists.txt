cmake_minimum_required(VERSION 3.26)
project(Project4)

set(CMAKE_CXX_STANDARD 17)

add_executable(Project4 main.cpp
        socket_methods.cpp
        socket_methods.h)
