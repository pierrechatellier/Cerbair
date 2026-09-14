#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include "infodrone/InfoDroneDecoder.hpp"

using namespace idp;

static wlan::VendorSpecificIe makeIe(std::vector<uint8_t> tlvs) {
    wlan::VendorSpecificIe ie;
    ie.oui = {0x6A, 0x5C, 0x35};
    ie.type = 0x01;
    ie.payload = std::move(tlvs);
    return ie;
}
static void putI32(std::vector<uint8_t>& v, int32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xFF);
}
static void putU16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(x & 0xFF);
    v.push_back((x >> 8) & 0xFF);
}

TEST_CASE("isInfoDrone: positive and negative") {
    auto ie = makeIe({});
    REQUIRE(infodrone::isInfoDrone(ie));
    ie.oui[0] = 0x00;
    REQUIRE_FALSE(infodrone::isInfoDrone(ie));
}

TEST_CASE("Full decode") {
    std::vector<uint8_t> t;
    t.push_back(0x01);
    t.push_back(0x01);
    t.push_back(0x03);
    const std::string fr = "FR-30TEST";
    t.push_back(0x02);
    t.push_back(uint8_t(fr.size()));
    t.insert(t.end(), fr.begin(), fr.end());
    const std::string ansi = "1ABCDEF";
    t.push_back(0x03);
    t.push_back(uint8_t(ansi.size()));
    t.insert(t.end(), ansi.begin(), ansi.end());
    t.push_back(0x04);
    t.push_back(0x04);
    putI32(t, 4881350);
    t.push_back(0x05);
    t.push_back(0x04);
    putI32(t, 231520);
    t.push_back(0x06);
    t.push_back(0x02);
    putU16(t, 105);
    t.push_back(0x07);
    t.push_back(0x02);
    putU16(t, 30);
    t.push_back(0x08);
    t.push_back(0x04);
    putI32(t, 4881000);
    t.push_back(0x09);
    t.push_back(0x04);
    putI32(t, 231000);
    t.push_back(0x0A);
    t.push_back(0x02);
    putU16(t, 52);
    t.push_back(0x0B);
    t.push_back(0x02);
    putU16(t, 1234);

    auto f = infodrone::decode(makeIe(t));
    REQUIRE(f.version == 3);
    REQUIRE(f.frId == "FR-30TEST");
    REQUIRE(f.ansiId == "1ABCDEF");
    REQUIRE(f.latitude == Catch::Approx(48.81350).margin(1e-6));
    REQUIRE(f.longitude == Catch::Approx(2.31520).margin(1e-6));
    REQUIRE(f.altitudeAmslM == Catch::Approx(105.0));
    REQUIRE(f.heightAglM == Catch::Approx(30.0));
    REQUIRE(f.takeoffLat == Catch::Approx(48.81).margin(1e-4));
    REQUIRE(f.takeoffLon == Catch::Approx(2.31).margin(1e-4));
    REQUIRE(f.groundSpeedMps == Catch::Approx(5.2));
    REQUIRE(f.trueCourseDeg == Catch::Approx(123.4));
    REQUIRE(f.warnings.empty());
}

TEST_CASE("Missing fields: defaults, no crash") {
    std::vector<uint8_t> t;
    t.push_back(0x04);
    t.push_back(0x04);
    putI32(t, 0);
    auto f = infodrone::decode(makeIe(t));
    REQUIRE(f.version == 0);
    REQUIRE(f.frId.empty());
    REQUIRE(f.latitude == Catch::Approx(0.0));
}

TEST_CASE("Truncated TLV produces warning") {
    std::vector<uint8_t> t = {0x02, 0x10, 'A', 'B'};
    auto f = infodrone::decode(makeIe(t));
    REQUIRE_FALSE(f.warnings.empty());
}

TEST_CASE("Unexpected length on lat/lon -> warning") {
    std::vector<uint8_t> t = {0x04, 0x02, 0x00, 0x00};
    auto f = infodrone::decode(makeIe(t));
    REQUIRE_FALSE(f.warnings.empty());
}
