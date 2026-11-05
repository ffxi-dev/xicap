cmake_minimum_required(VERSION 3.21)
project(xicap_python LANGUAGES CXX)

# The library goes into a shared module, so zstd is built here with -fPIC.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(XICAP_FETCH_ZSTD ON CACHE BOOL "" FORCE)
add_subdirectory(../.. xicap)

find_package(pybind11 CONFIG REQUIRED)
pybind11_add_module(xicap_module src/bindings.cpp)
set_target_properties(xicap_module PROPERTIES OUTPUT_NAME xicap)
target_link_libraries(xicap_module PRIVATE xicap)
install(TARGETS xicap_module LIBRARY DESTINATION .)
