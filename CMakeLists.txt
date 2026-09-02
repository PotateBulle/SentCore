cmake_minimum_required(VERSION 3.25)

project(
    SentCore
    VERSION 0.1.0
    DESCRIPTION "High-performance Linux endpoint detection engine"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(sentcore
    src/main.cpp
)

target_compile_options(sentcore
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wformat=2
        -Wnull-dereference
)

target_include_directories(sentcore
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

option(
    SENTCORE_ENABLE_SANITIZERS
    "Enable runtime sanitizers for development builds"
    OFF
)