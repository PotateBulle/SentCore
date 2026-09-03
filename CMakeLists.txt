cmake_minimum_required(VERSION 3.25)

project(
    SentCore
    VERSION 0.1.0
    DESCRIPTION "High-performance Linux endpoint detection engine"
    LANGUAGES CXX
)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "SentCore currently supports Linux only.")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SENTCORE_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(SENTCORE_BUILD_TESTS "Build SentCore tests" ON)
option(SENTCORE_BUILD_BENCHMARKS "Build SentCore micro-benchmarks" ON)
option(SENTCORE_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

find_package(Threads REQUIRED)

configure_file(
    ${PROJECT_SOURCE_DIR}/cmake/version.hpp.in
    ${PROJECT_BINARY_DIR}/generated/sentcore/version.hpp
    @ONLY
)

function(sentcore_apply_project_options target)
    target_compile_options(${target}
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

    if(SENTCORE_WARNINGS_AS_ERRORS)
        target_compile_options(${target} PRIVATE -Werror)
    endif()

    if(SENTCORE_ENABLE_SANITIZERS)
        if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
            target_compile_options(${target}
                PRIVATE
                    -fsanitize=address,undefined
                    -fno-omit-frame-pointer
            )
            target_link_options(${target}
                PRIVATE
                    -fsanitize=address,undefined
            )
        else()
            message(WARNING "Sanitizers are currently supported only with Clang and GCC.")
        endif()
    endif()
endfunction()

add_library(sentcore_core
    src/core/agent.cpp
    src/collectors/filesystem_collector.cpp
    src/collectors/process_collector.cpp
    src/detection/detection_engine.cpp
    src/output/jsonl_writer.cpp
)

target_include_directories(sentcore_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_BINARY_DIR}/generated
)

target_link_libraries(sentcore_core PUBLIC Threads::Threads)
sentcore_apply_project_options(sentcore_core)

add_executable(sentcore src/main.cpp)
target_link_libraries(sentcore PRIVATE sentcore_core)
sentcore_apply_project_options(sentcore)

include(CTest)

if(BUILD_TESTING AND SENTCORE_BUILD_TESTS)
    add_executable(sentcore_tests tests/test_detection.cpp)
    target_link_libraries(sentcore_tests PRIVATE sentcore_core)
    sentcore_apply_project_options(sentcore_tests)
    add_test(NAME sentcore_detection_tests COMMAND sentcore_tests)
endif()

if(SENTCORE_BUILD_BENCHMARKS)
    add_executable(sentcore_event_benchmark benchmarks/event_benchmark.cpp)
    target_link_libraries(sentcore_event_benchmark PRIVATE sentcore_core)
    sentcore_apply_project_options(sentcore_event_benchmark)
endif()
