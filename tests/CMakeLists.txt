include(FetchContent)
FetchContent_Declare(Catch2
    URL https://github.com/catchorg/Catch2/archive/refs/tags/v3.8.1.tar.gz
    URL_HASH SHA256=18b3f70ac80fccc340d8c6ff0f339b2ae64944782f8d2fca2bd705cf47cadb79)
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa)
FetchContent_MakeAvailable(Catch2 json)

add_executable(xicap_tests
    columns_test.cpp
    redaction_test.cpp
    reader_test.cpp
    stream_reader_test.cpp
    transcode_test.cpp
    vectors_test.cpp
    writer_test.cpp)
target_link_libraries(xicap_tests PRIVATE xicap Catch2::Catch2WithMain nlohmann_json::nlohmann_json)
# Tests reach into src/ to craft damaged files.
target_include_directories(xicap_tests PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(xicap_tests PRIVATE ${XICAP_ZSTD})
target_compile_definitions(xicap_tests PRIVATE VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors")

add_executable(make_vectors make_vectors.cpp)
target_link_libraries(make_vectors PRIVATE xicap nlohmann_json::nlohmann_json ${XICAP_ZSTD})
target_include_directories(make_vectors PRIVATE ${PROJECT_SOURCE_DIR}/src)

include(${catch2_SOURCE_DIR}/extras/Catch.cmake)
catch_discover_tests(xicap_tests)
