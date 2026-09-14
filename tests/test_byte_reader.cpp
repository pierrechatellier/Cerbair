#include <catch2/catch_test_macros.hpp>
#include "common/ByteReader.hpp"

TEST_CASE("ByteReader little-endian") {
    uint8_t buf[8] = {0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD};
    idp::ByteReader r(buf, sizeof(buf), true);
    REQUIRE(r.u8()  == 0x01);
    REQUIRE(r.u16() == 0x0302);
    REQUIRE(r.u32() == 0xDDCCBBAA);
    REQUIRE(r.remaining() == 0);
}

TEST_CASE("ByteReader big-endian") {
    uint8_t buf[4] = {0x01, 0x02, 0x03, 0x04};
    idp::ByteReader r(buf, sizeof(buf), false);
    REQUIRE(r.u32() == 0x01020304);
}

TEST_CASE("ByteReader signed int32") {
    uint8_t buf[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    idp::ByteReader r(buf, 4, true);
    REQUIRE(r.i32() == -1);
}

TEST_CASE("ByteReader out-of-bounds throws") {
    uint8_t buf[2] = {0, 0};
    idp::ByteReader r(buf, 2, true);
    REQUIRE_THROWS_AS(r.u32(), idp::ParseError);
}
