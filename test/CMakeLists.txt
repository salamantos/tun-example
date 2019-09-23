cmake_minimum_required(VERSION 3.5)

project(NetPlaygroundTest VERSION 1.0)
set(CMAKE_CXX_STANDARD 17)

add_executable(server server.cpp ../c/cnets.c)
target_include_directories(server PRIVATE ../include ..)
