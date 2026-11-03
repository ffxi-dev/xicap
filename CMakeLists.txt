cmake_minimum_required(VERSION 3.16)
project(xicap VERSION 4.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 32-bit build option (for non-MSVC compilers)
# Note: For MSVC, use the x86 Native Tools Command Prompt or pass -A Win32 to cmake
option(XICAP_BUILD_32BIT "Build for 32-bit architecture (non-MSVC only)" OFF)
if(XICAP_BUILD_32BIT AND NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
endif()

# Find zstd or fetch it. A shared module needs zstd built with -fPIC, which a system libzstd.a may not be.
option(XICAP_FETCH_ZSTD "Build zstd from source even when the system has it" OFF)
if(NOT XICAP_FETCH_ZSTD)
    find_package(zstd CONFIG QUIET)
    if(NOT zstd_FOUND)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(ZSTD IMPORTED_TARGET libzstd)
        endif()
    endif()
endif()

if(NOT zstd_FOUND AND NOT ZSTD_FOUND)
    message(STATUS "zstd not found, fetching via FetchContent...")
    include(FetchContent)

    set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)

    unset(CMAKE_GENERATOR_PLATFORM CACHE)

    FetchContent_Declare(
        zstd
        GIT_REPOSITORY https://github.com/facebook/zstd.git
        GIT_TAG        v1.5.7
        SOURCE_SUBDIR  build/cmake
    )
    FetchContent_MakeAvailable(zstd)

    set(ZSTD_FETCHED TRUE)
endif()

set(XICAP_SOURCES
    src/columns.cpp
    src/decoder.cpp
    src/reader.cpp
    src/stream_reader.cpp
    src/transcode.cpp
    src/writer.cpp
    third_party/monocypher/monocypher.c
    third_party/monocypher/optional/monocypher-ed25519.c
)

set(XICAP_HEADERS
    include/xicap/xicap.h
    include/xicap/types.h
    include/xicap/constants.h
    include/xicap/writer.h
    include/xicap/reader.h
    include/xicap/stream_reader.h
    include/xicap/transcode.h
)

add_library(xicap STATIC ${XICAP_SOURCES} ${XICAP_HEADERS})

target_include_directories(xicap
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher
)

if(zstd_FOUND)
    target_link_libraries(xicap PUBLIC zstd::libzstd_static)
elseif(TARGET PkgConfig::ZSTD)
    target_link_libraries(xicap PUBLIC PkgConfig::ZSTD)
elseif(ZSTD_FETCHED)
    target_link_libraries(xicap PUBLIC libzstd_static)
endif()

install(TARGETS xicap
    EXPORT xicapTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(DIRECTORY include/xicap
    DESTINATION include
)

install(EXPORT xicapTargets
    FILE xicapTargets.cmake
    NAMESPACE xicap::
    DESTINATION lib/cmake/xicap
)

# Tools
option(XICAP_BUILD_TOOLS "Build xicap tools" ON)
if(XICAP_BUILD_TOOLS)
    add_executable(xicap_dump tools/xicap_dump.cpp)
    target_link_libraries(xicap_dump PRIVATE xicap)
endif()

# Fixture generator (no Ashita SDK needed; used by the JS test suite).
option(XICAP_BUILD_FIXTURE_TOOL "Build the xicap_make_fixture helper" OFF)
if(XICAP_BUILD_FIXTURE_TOOL)
    add_executable(xicap_make_fixture tools/xicap_make_fixture.cpp)
    target_link_libraries(xicap_make_fixture PRIVATE xicap)
endif()

# Conformance set generator (writes tests/vectors).
option(XICAP_BUILD_VECTOR_TOOL "Build the xicap_make_vectors generator" OFF)
if(XICAP_BUILD_VECTOR_TOOL)
    add_executable(xicap_make_vectors tools/xicap_make_vectors.cpp)
    target_link_libraries(xicap_make_vectors PRIVATE xicap)
    target_include_directories(xicap_make_vectors PRIVATE src tools third_party/monocypher)
endif()

# Tests
option(XICAP_BUILD_TESTS "Build xicap tests" OFF)
if(XICAP_BUILD_TESTS)
    enable_testing()
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.5.4
    )
    FetchContent_MakeAvailable(Catch2)

    add_executable(xicap_tests tests/xicap_tests.cpp tests/format4_tests.cpp)
    target_link_libraries(xicap_tests PRIVATE xicap Catch2::Catch2WithMain)
    # Tests reach into src/internal to rebuild CRCs and chains when crafting bad files.
    target_include_directories(xicap_tests PRIVATE src tools third_party/monocypher)
    target_compile_definitions(xicap_tests PRIVATE XICAP_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors")

    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
    include(Catch)
    catch_discover_tests(xicap_tests)
endif()
