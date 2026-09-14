#pragma once
#include <cstdint>
#include <fstream>
#include <istream>
#include <string>
#include <vector>
#include "common/ByteReader.hpp"

namespace idp::pcapng {

constexpr uint32_t kSectionHeaderBlock        = 0x0A0D0D0A;
constexpr uint32_t kInterfaceDescriptionBlock = 0x00000001;
constexpr uint32_t kPacketBlock               = 0x00000002;
constexpr uint32_t kSimplePacketBlock         = 0x00000003;
constexpr uint32_t kNameResolutionBlock       = 0x00000004;
constexpr uint32_t kInterfaceStatisticsBlock  = 0x00000005;
constexpr uint32_t kEnhancedPacketBlock       = 0x00000006;

constexpr uint16_t kLinkTypeEthernet  = 1;
constexpr uint16_t kLinkTypeIeee80211 = 105;
constexpr uint16_t kLinkTypeRadiotap  = 127;

struct Packet {
    uint32_t interfaceId   = 0;
    uint64_t timestampNs   = 0;
    uint16_t linkType      = 0;
    std::vector<uint8_t> data;
};

class PcapNgReader {
public:
    explicit PcapNgReader(std::istream& in) : in_(&in) {}
    explicit PcapNgReader(const std::string& path)
        : file_(path, std::ios::binary) {
        if (!file_) throw std::runtime_error("Cannot open pcapng: " + path);
        in_ = &file_;
    }

    bool next(Packet& out);

    const std::vector<uint16_t>& interfaceLinkTypes() const { return linkTypes_; }

private:
    void readExact(void* dst, size_t n, const char* what);

    std::ifstream file_;
    std::istream* in_ = nullptr;
    bool     littleEndian_  = true;
    bool     byteOrderSeen_ = false;
    std::vector<uint16_t> linkTypes_;
};

} // namespace idp::pcapng
