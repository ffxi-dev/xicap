cmake_minimum_required(VERSION 3.16)
project(xicap_python LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Pull xicap (lib only) in as a subproject. The xicap static lib gets linked
# into a Python shared module, so on Linux we need position-independent code
# everywhere (including zstd, which is also a static lib via FetchContent).
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(XICAP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(XICAP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(XICAP_FETCH_ZSTD ON CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. xicap_lib)

# pybind11 — fetched if not provided by the build environment.
find_package(pybind11 CONFIG QUIET)
if(NOT pybind11_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        pybind11
        GIT_REPOSITORY https://github.com/pybind/pybind11.git
        GIT_TAG        v2.13.6
    )
    FetchContent_MakeAvailable(pybind11)
endif()

pybind11_add_module(_xicap src/bindings.cpp)
target_link_libraries(_xicap PRIVATE xicap)

# scikit-build-core honours this for wheel layout (module ends up at
# xicap/_xicap.<abi>.pyd).
if(SKBUILD)
    install(TARGETS _xicap LIBRARY DESTINATION xicap)
endif()
