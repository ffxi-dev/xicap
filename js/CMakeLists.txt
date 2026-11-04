cmake_minimum_required(VERSION 3.21)
project(xicap_wasm LANGUAGES CXX)

if(NOT EMSCRIPTEN)
    message(FATAL_ERROR "Configure with emcmake.")
endif()

add_subdirectory(.. xicap)
target_compile_options(xicap PUBLIC -fexceptions)

add_executable(xicap_wasm src/bindings.cpp)
target_link_libraries(xicap_wasm PRIVATE xicap)
target_compile_options(xicap_wasm PRIVATE -O3)
# An ES module with a factory, for browsers and Node; MEMFS holds the bytes Reader.open reads.
target_link_options(xicap_wasm PRIVATE -O3 -fexceptions -lembind -sMODULARIZE -sEXPORT_ES6 -sEXPORT_NAME=createXicap
    -sENVIRONMENT=web,worker,node -sALLOW_MEMORY_GROWTH -sEXPORTED_RUNTIME_METHODS=FS)
set_target_properties(xicap_wasm PROPERTIES OUTPUT_NAME xicap SUFFIX .js RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/dist)
