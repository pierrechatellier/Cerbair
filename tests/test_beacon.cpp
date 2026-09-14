#include <catch2/catch_test_macros.hpp>
#include "wlan/WlanFrame.hpp"
#include "pcapng/PcapNgReader.hpp"

using namespace idp;

static std::vector<uint8_t> makeBeacon(uint8_t ssidTag,
                                       const std::string& ssid,
                                       const std::vector<uint8_t>& vendorIe) {
    std::vector<uint8_t> f;
    f.resize(24, 0);
    f[0] = 0x80;
    for (int i = 0; i < 6; ++i) f[16 + i] = 0x11 * (i + 1);
    f.resize(24 + 12, 0);
    f.push_back(ssidTag);
    f.push_back(static_cast<uint8_t>(ssid.size()));
    f.insert(f.end(), ssid.begin(), ssid.end());
    f.insert(f.end(), vendorIe.begin(), vendorIe.end());
    return f;
}

TEST_CASE("Beacon: parse SSID and BSSID") {
    auto buf = makeBeacon(0, "ANAFI-TEST", {});
    auto b = wlan::parseBeacon(buf.data(), buf.size(),
                               pcapng::kLinkTypeIeee80211);
    REQUIRE(b.has_value());
    REQUIRE(b->ssid == "ANAFI-TEST");
    REQUIRE(b->bssid[0] == 0x11);
}

TEST_CASE("Beacon: vendor IE extracted") {
    std::vector<uint8_t> vs = {0xDD, 0x06, 0x6A, 0x5C, 0x35, 0x01, 'A', 'B'};
    auto buf = makeBeacon(0, "x", vs);
    auto b = wlan::parseBeacon(buf.data(), buf.size(),
                               pcapng::kLinkTypeIeee80211);
    REQUIRE(b.has_value());
    REQUIRE(b->vendorIes.size() == 1);
    REQUIRE(b->vendorIes[0].oui[0] == 0x6A);
    REQUIRE(b->vendorIes[0].type   == 0x01);
    REQUIRE(b->vendorIes[0].payload.size() == 2);
}

TEST_CASE("Non-beacon frame returns nullopt") {
    std::vector<uint8_t> f(64, 0);
    f[0] = 0x40;
    auto b = wlan::parseBeacon(f.data(), f.size(),
                               pcapng::kLinkTypeIeee80211);
    REQUIRE_FALSE(b.has_value());
}

TEST_CASE("Truncated IE stops parsing without throwing") {
    auto buf = makeBeacon(0, "abc", {});
    buf.push_back(0xDD); buf.push_back(0xFF);
    auto b = wlan::parseBeacon(buf.data(), buf.size(),
                               pcapng::kLinkTypeIeee80211);
    REQUIRE(b.has_value());
    REQUIRE(b->ssid == "abc");
}
