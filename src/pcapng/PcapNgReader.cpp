#include "pcapng/PcapNgReader.hpp"
#include "common/ByteReader.hpp"

#include <cstring>

namespace idp::pcapng {

static uint32_t rdU32(const uint8_t* p, bool le) {
    if (le) return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
                 | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
         | (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
}
static uint16_t rdU16(const uint8_t* p, bool le) {
    return le ? uint16_t(p[0] | (p[1] << 8)) : uint16_t((p[0] << 8) | p[1]);
}

void PcapNgReader::readExact(void* dst, size_t n, const char* what) {
    in_->read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(n));
    if (static_cast<size_t>(in_->gcount()) != n)
        throw ParseError(std::string("pcapng: short read on ") + what);
}

bool PcapNgReader::next(Packet& out) {
    while (true) {
        uint8_t hdr[8];
        in_->read(reinterpret_cast<char*>(hdr), 8);
        auto got = in_->gcount();
        if (got == 0) return false;
        if (got != 8) throw ParseError("pcapng: truncated block header");

        const bool isShb = hdr[0] == 0x0A && hdr[1] == 0x0D
                        && hdr[2] == 0x0D && hdr[3] == 0x0A;

        uint32_t blockType;
        uint32_t totalLen;

        if (isShb) {
            uint8_t magic[4];
            readExact(magic, 4, "SHB byte-order magic");
            if (magic[0]==0x4D && magic[1]==0x3C && magic[2]==0x2B && magic[3]==0x1A)
                littleEndian_ = true;
            else if (magic[0]==0x1A && magic[1]==0x2B && magic[2]==0x3C && magic[3]==0x4D)
                littleEndian_ = false;
            else
                throw ParseError("pcapng: invalid byte-order magic");
            byteOrderSeen_ = true;

            blockType = kSectionHeaderBlock;
            totalLen  = rdU32(hdr + 4, littleEndian_);
            if (totalLen < 16 || (totalLen & 3))
                throw ParseError("pcapng: invalid SHB length");

            size_t rest = totalLen - 16;
            in_->seekg(static_cast<std::streamoff>(rest), std::ios::cur);
            uint8_t trailer[4];
            readExact(trailer, 4, "SHB trailer");
            if (rdU32(trailer, littleEndian_) != totalLen)
                throw ParseError("pcapng: SHB length trailer mismatch");
            continue;
        }

        if (!byteOrderSeen_)
            throw ParseError("pcapng: block before Section Header Block");

        blockType = rdU32(hdr,     littleEndian_);
        totalLen  = rdU32(hdr + 4, littleEndian_);
        if (totalLen < 12 || (totalLen & 3))
            throw ParseError("pcapng: invalid block length");

        std::vector<uint8_t> body(totalLen - 12);
        if (!body.empty())
            readExact(body.data(), body.size(), "block body");
        uint8_t trailer[4];
        readExact(trailer, 4, "block trailer");
        if (rdU32(trailer, littleEndian_) != totalLen)
            throw ParseError("pcapng: block length trailer mismatch");

        switch (blockType) {
        case kInterfaceDescriptionBlock: {
            if (body.size() < 8) throw ParseError("pcapng: IDB too short");
            uint16_t lt = rdU16(body.data(), littleEndian_);
            linkTypes_.push_back(lt);
            continue;
        }
        case kEnhancedPacketBlock: {
            if (body.size() < 20) throw ParseError("pcapng: EPB too short");
            uint32_t iface = rdU32(body.data() +  0, littleEndian_);
            uint32_t tsHi  = rdU32(body.data() +  4, littleEndian_);
            uint32_t tsLo  = rdU32(body.data() +  8, littleEndian_);
            uint32_t capLen= rdU32(body.data() + 12, littleEndian_);
            if (body.size() < 20 + capLen)
                throw ParseError("pcapng: EPB payload truncated");

            out.interfaceId = iface;
            out.timestampNs = (uint64_t(tsHi) << 32) | tsLo;
            out.linkType    = iface < linkTypes_.size() ? linkTypes_[iface] : 0;
            out.data.assign(body.begin() + 20, body.begin() + 20 + capLen);
            return true;
        }
        case kSimplePacketBlock: {
            if (body.size() < 4) throw ParseError("pcapng: SPB too short");
            out.interfaceId = 0;
            out.timestampNs = 0;
            out.linkType    = linkTypes_.empty() ? 0 : linkTypes_[0];
            out.data.assign(body.begin() + 4, body.end());
            return true;
        }
        default:
            continue;
        }
    }
}

} // namespace idp::pcapng
