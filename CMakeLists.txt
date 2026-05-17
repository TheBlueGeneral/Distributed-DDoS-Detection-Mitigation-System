# CMakeLists.txt
cmake_minimum_required(VERSION 3.22)
project(EdgeGuardPlatform LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure build profiles 
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "production" CACHE STRING "Choose build profile" FORCE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "production")
    set(CMAKE_CXX_FLAGS "-O3 -march=native -flto -DNDEBUG")
elseif(CMAKE_BUILD_TYPE STREQUAL "debug")
    set(CMAKE_CXX_FLAGS "-O0 -g3")
elseif(CMAKE_BUILD_TYPE STREQUAL "TSAN")
    set(CMAKE_CXX_FLAGS "-O1 -g3 -fsanitize=thread")
elseif(CMAKE_BUILD_TYPE STREQUAL "ASAN")
    set(CMAKE_CXX_FLAGS "-O1 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer")
endif()

find_package(Threads REQUIRED)

# Locate shared client libraries [5, 22, 35]
find_library(BPF_LIBRARY bpf REQUIRED)
find_library(HIREDIS_LIBRARY hiredis REQUIRED)
find_library(RDKAFKA_LIBRARY rdkafkacpp REQUIRED)

# Standard header paths
include_directories(/usr/local/include)

# Compile user-space agent binary
add_executable(edge_guard_agent 
    main.cpp
)
target_link_libraries(edge_guard_agent 
    PRIVATE 
    Threads::Threads 
    ${BPF_LIBRARY} 
    ${HIREDIS_LIBRARY} 
    ${RDKAFKA_LIBRARY}
)
target_compile_definitions(edge_guard_agent PRIVATE RUN_XDP)

# Custom target to compile restricted C packet filter to BPF bytecode 
add_custom_target(xdp_kernel_bytecode
    COMMAND clang -O2 -g -Wall -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/xdp_firewall_kernel.c -o ${CMAKE_CURRENT_BINARY_DIR}/xdp_firewall_kernel.o
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Compiling restricted C packet filter to BPF bytecode target..."
)
add_dependencies(edge_guard_agent xdp_kernel_bytecode)
