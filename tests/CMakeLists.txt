include(FetchContent)
FetchContent_Declare(Catch2 GIT_REPOSITORY https://github.com/catchorg/Catch2.git GIT_TAG v3.8.1)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(Catch2 json)

add_executable(xicap_tests
    columns_test.cpp
    policy_test.cpp
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

if(XICAP_BUILD_FUZZERS)
    foreach(target reader columns)
        add_executable(fuzz_${target} fuzz/${target}.cpp)
        target_link_libraries(fuzz_${target} PRIVATE xicap ${XICAP_ZSTD})
        target_include_directories(fuzz_${target} PRIVATE ${PROJECT_SOURCE_DIR}/src)
        target_compile_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
        target_link_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
    endforeach()
endif()
