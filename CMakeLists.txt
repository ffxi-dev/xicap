cmake_minimum_required(VERSION 3.21)
project(xicap VERSION 7.1.1 LANGUAGES CXX)

option(XICAP_FETCH_ZSTD "Build zstd from source even when the system has it" OFF)
option(XICAP_BUILD_TESTS "Build the tests" OFF)
option(XICAP_BUILD_FUZZERS "Build the libFuzzer targets (Clang)" OFF)

if(XICAP_BUILD_FUZZERS AND XICAP_BUILD_TESTS)
    message(FATAL_ERROR "XICAP_BUILD_FUZZERS skips CRC checks in the library; build the tests in another directory")
endif()

if(NOT XICAP_FETCH_ZSTD)
    find_package(zstd 1.4 CONFIG QUIET)
    if(NOT zstd_FOUND)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(ZSTD IMPORTED_TARGET libzstd>=1.4.0)
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
    FetchContent_Declare(zstd
        URL https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz
        URL_HASH SHA256=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3
        SOURCE_SUBDIR build/cmake)
    FetchContent_MakeAvailable(zstd)
    set(XICAP_ZSTD libzstd_static)
endif()

# bindings/go/library.cpp includes these files too, since cgo builds one folder; keep both lists in step.
add_library(xicap STATIC
    src/frame/columns_decode.cpp
    src/frame/columns_encode.cpp
    src/frame/decoder.cpp
    src/frame/encoder.cpp
    src/frame/frame.cpp
    src/io/reader.cpp
    src/io/stream_reader.cpp
    src/io/transcode.cpp
    src/io/writer.cpp
    src/metadata/decode.cpp
    src/metadata/encode.cpp
    src/redaction/redaction.cpp)
target_include_directories(xicap PUBLIC include PRIVATE src)
target_compile_features(xicap PUBLIC cxx_std_23)
target_link_libraries(xicap PRIVATE ${XICAP_ZSTD})

if(XICAP_BUILD_FUZZERS)
    target_compile_options(xicap PRIVATE -fsanitize=fuzzer-no-link,address)
    target_compile_definitions(xicap PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    add_subdirectory(tests/fuzz)
endif()

if(XICAP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
