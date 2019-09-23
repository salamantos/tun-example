cmake_minimum_required(VERSION 3.5)

project(NetPlayground VERSION 1.0)
set(CMAKE_CXX_STANDARD 17)

find_package(Threads REQUIRED)
link_libraries(${CMAKE_THREAD_LIBS_INIT})

option(USE_TS "Use thread sanitizer" OFF)
option(USE_AS "Use address sanitizer" OFF)

set(SANITIZERS "")
if (USE_TS)
    set(SANITIZERS "-fsanitize=thread")
elseif(USE_AS)
    set(SANITIZERS "-fsanitize=address")
endif()

add_executable(plg cpp/main.cpp c/tuns.c c/cnets.c c/namespaces.c)
target_include_directories(plg PRIVATE include/)

target_compile_options(plg PRIVATE "-Wall;-Wextra;${SANITIZERS}")
set(CMAKE_EXE_LINKER_FLAGS "${SANITIZERS}")

add_subdirectory(test)