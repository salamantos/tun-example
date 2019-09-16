cmake_minimum_required(VERSION 3.5)

project(TunExperimental VERSION 1.0)

add_executable(main src/main.cpp src/tuns.c)
target_include_directories(main PRIVATE include/)
