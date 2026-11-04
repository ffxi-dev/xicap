cmake_minimum_required(VERSION 3.16)
project(xicap_wasm LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT EMSCRIPTEN)
    message(FATAL_ERROR "Configure with emcmake; this CMakeLists is Emscripten-only.")
endif()

# The library as a subproject, without its tools and tests.
set(XICAP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(XICAP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. xicap_lib)

add_executable(xicap_wasm src/bindings.cpp)
target_link_libraries(xicap_wasm PRIVATE xicap)

# An ES module exporting the factory createXicap, for browsers and Node. The heap grows with the capture, which
# Reader.open writes to MEMFS through the exported FS. C++ exceptions reach JS as thrown errors. The stack is 1 MB.
target_link_options(xicap_wasm PRIVATE
    "-lembind"
    "-sMODULARIZE=1"
    "-sEXPORT_ES6=1"
    "-sEXPORT_NAME=createXicap"
    "-sENVIRONMENT=web,node"
    "-sALLOW_MEMORY_GROWTH=1"
    "-sFILESYSTEM=1"
    "-sEXPORTED_RUNTIME_METHODS=['FS']"
    "-fexceptions"
    "-sSTACK_SIZE=1048576"
    "-O3"
)
target_compile_options(xicap_wasm PRIVATE "-fexceptions" "-O3")
# The library too, or withJsErrors never sees an xicap::Error.
target_compile_options(xicap PUBLIC "-fexceptions")
target_link_options(xicap PUBLIC "-fexceptions")

set_target_properties(xicap_wasm PROPERTIES
    OUTPUT_NAME "xicap"
    SUFFIX ".js"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/dist"
)
