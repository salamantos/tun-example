cmake_minimum_required(VERSION 3.5)

project(TunExperimental VERSION 1.0)
set(CMAKE_CXX_STANDARD 17)

find_package(Threads REQUIRED)
link_libraries(${CMAKE_THREAD_LIBS_INIT})


#set(USE_AS ON)
#set(USE_TS ON)

set(SANITIZERS "")
if (USE_TS)
    set(SANITIZERS "-fsanitize=thread")
elseif(USE_AS)
    set(SANITIZERS "-fsanitize=address")
endif()

add_executable(main cpp/main.cpp c/tuns.c c/cnets.c c/namespaces.c)
target_include_directories(main PRIVATE include/)

target_compile_options(main PRIVATE "-Wall;-Wextra;${SANITIZERS}")
set(CMAKE_EXE_LINKER_FLAGS "${SANITIZERS}")
