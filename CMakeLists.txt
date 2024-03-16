cmake_minimum_required(VERSION 3.21)
project(raw_socket_sniffer)

set(CMAKE_CXX_STANDARD 20)

add_executable(raw_socket_sniffer main.cpp
        socket_sniffer.cpp
        socket_sniffer.h)
