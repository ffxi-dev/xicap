cmake_minimum_required(VERSION 3.21)
project(xicap VERSION 7.1.1 LANGUAGES CXX)

option(XICAP_FETCH_ZSTD "Build zstd from source even when the system has it" OFF)
option(XICAP_BUILD_TESTS "Build the tests" OFF)
option(XICAP_BUILD_FUZZERS "Build the libFuzzer targets (Clang)" OFF)

if(NOT XICAP_FETCH_ZSTD)
    find_package(zstd CONFIG QUIET)
    if(NOT zstd_FOUND)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(ZSTD IMPORTED_TARGET libzstd)
        endif()
    endif()
endif()

if(TARGET zstd::libzstd_static)
    set(XICAP_ZSTD zstd::libzstd_static)
elseif(TARGET zstd::libzstd_shared)
    set(XICAP_ZSTD zstd::libzstd_shared)
elseif(TARGET PkgConfig::ZSTD)
    set(XICAP_ZSTD PkgConfig::ZSTD)
else()
    include(FetchContent)
    set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(zstd GIT_REPOSITORY https://github.com/facebook/zstd.git GIT_TAG v1.5.7 SOURCE_SUBDIR build/cmake)
    FetchContent_MakeAvailable(zstd)
    set(XICAP_ZSTD libzstd_static)
endif()

add_library(xicap STATIC
    src/decode_columns.cpp
    src/decode_metadata.cpp
    src/encode_columns.cpp
    src/encode_metadata.cpp
    src/frame.cpp
    src/frame_decoder.cpp
    src/policy.cpp
    src/reader.cpp
    src/stream_reader.cpp
    src/transcode.cpp
    src/writer.cpp)
target_include_directories(xicap PUBLIC include)
target_compile_features(xicap PUBLIC cxx_std_23)
target_link_libraries(xicap PRIVATE ${XICAP_ZSTD})

if(XICAP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
