cmake_minimum_required(VERSION 3.5)

project(TunExperimental VERSION 1.0)
set(CMAKE_CXX_STANDARD 17)

find_package(Threads REQUIRED)
link_libraries(${CMAKE_THREAD_LIBS_INIT})

add_executable(main src/main.cpp src/tuns.c src/rawsocket.c src/cnets.c src/namespaces.c)
target_include_directories(main PRIVATE include/)
