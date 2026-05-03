cmake_minimum_required(VERSION 3.16)
project(xicap_wasm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT EMSCRIPTEN)
    message(FATAL_ERROR "Configure with emcmake; this CMakeLists is Emscripten-only.")
endif()

# Pull the xicap library in as a subproject. Tools and tests are off.
set(XICAP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(XICAP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. xicap_lib)

add_executable(xicap_wasm src/bindings.cpp)
target_link_libraries(xicap_wasm PRIVATE xicap)

# Emscripten link flags:
#  -lembind                  : C++ <-> JS bindings runtime
#  -sMODULARIZE              : factory function module instead of globals
#  -sEXPORT_ES6              : ES module output
#  -sEXPORT_NAME=createXicap : factory name
#  -sENVIRONMENT=web,node    : both browser and Node
#  -sALLOW_MEMORY_GROWTH=1   : grow heap as needed (captures vary in size)
#  -sEXPORTED_RUNTIME_METHODS=FS : expose MEMFS bindings to JS for input bytes
#  -sFILESYSTEM=1            : enable MEMFS
#  -sNO_DISABLE_EXCEPTION_CATCHING : C++ exceptions cross into JS as thrown errors
#  -sSTACK_SIZE=1MB          : zstd dict load uses ~256 KB stack at compression init
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
# xicap library needs to compile with -fexceptions too, otherwise our catch
# handlers in withJsErrors silently miss thrown xicap::Error instances.
target_compile_options(xicap PUBLIC "-fexceptions")
target_link_options(xicap PUBLIC "-fexceptions")

set_target_properties(xicap_wasm PROPERTIES
    OUTPUT_NAME "xicap"
    SUFFIX ".js"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/dist"
)
