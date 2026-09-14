#include <catch2/catch_test_macros.hpp>
#include <sstream>

#include "pcapng/PcapNgReader.hpp"

using namespace idp;

static void putU32LE(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xFF);
}
static void putU16LE(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(x & 0xFF);
    v.push_back((x >> 8) & 0xFF);
}

static std::vector<uint8_t> buildMinimalPcapng() {
    std::vector<uint8_t> b;

    b.insert(b.end(), {0x0A, 0x0D, 0x0D, 0x0A});
    putU32LE(b, 28);
    putU32LE(b, 0x1A2B3C4D);
    putU16LE(b, 1);
    putU16LE(b, 0);
    for (int i = 0; i < 8; ++i) b.push_back(0xFF);
    putU32LE(b, 28);

    putU32LE(b, 0x00000001);
    putU32LE(b, 20);
    putU16LE(b, 105);
    putU16LE(b, 0);
    putU32LE(b, 65535);
    putU32LE(b, 20);

    std::vector<uint8_t> data(8, 0xAB);
    uint32_t bodyLen = 20 + static_cast<uint32_t>(data.size());
    uint32_t totalLen = 12 + bodyLen;
    putU32LE(b, 0x00000006);
    putU32LE(b, totalLen);
    putU32LE(b, 0);
    putU32LE(b, 0);
    putU32LE(b, 42);
    putU32LE(b, (uint32_t)data.size());
    putU32LE(b, (uint32_t)data.size());
    b.insert(b.end(), data.begin(), data.end());
    putU32LE(b, totalLen);
    return b;
}

TEST_CASE("pcapng: read one EPB") {
    auto bytes = buildMinimalPcapng();
    std::string s(bytes.begin(), bytes.end());
    std::istringstream in(s);

    pcapng::PcapNgReader r(in);
    pcapng::Packet pkt;
    REQUIRE(r.next(pkt));
    REQUIRE(pkt.interfaceId == 0);
    REQUIRE(pkt.linkType == 105);
    REQUIRE(pkt.data.size() == 8);
    REQUIRE(pkt.data[0] == 0xAB);
    REQUIRE_FALSE(r.next(pkt));
}

TEST_CASE("pcapng: corrupted length trailer throws") {
    auto bytes = buildMinimalPcapng();
    bytes[bytes.size() - 4] = 0x00;
    std::string s(bytes.begin(), bytes.end());
    std::istringstream in(s);

    pcapng::PcapNgReader r(in);
    pcapng::Packet pkt;
    REQUIRE_THROWS_AS(r.next(pkt), ParseError);
}
