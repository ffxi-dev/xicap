#include "describe.h"

#include <catch2/catch_test_macros.hpp>

#include <fstream>

TEST_CASE("every vector reads as its JSON says")
{
    int count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(VECTORS_DIR))
    {
        if (entry.path().extension() != ".xicap")
        {
            continue;
        }

        INFO(entry.path().filename().string());
        const auto want = nlohmann::ordered_json::parse(std::ifstream(std::filesystem::path(entry.path()).replace_extension(".json")));
        CHECK(test::describe(entry.path()) == want);
        count++;
    }

    CHECK(count >= 15);
}
