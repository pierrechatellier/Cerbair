#include "wlan/WlanFrame.hpp"
#include "pcapng/PcapNgReader.hpp"

#include <cstring>

namespace idp::wlan {

namespace {

bool parseRadiotap(const uint8_t* data, size_t len,
                   bool& hasRssi, int& rssi, size_t& rtLenOut) {
    // Radiotap indique sa propre longueur afin de permettre l'acces a la
    // trame 802.11 qui suit, quelle que soit la taille de ses metadonnees.
    if (len < 8 || data[0] != 0) return false;
    uint16_t rtLen = uint16_t(data[2] | (data[3] << 8));
    if (rtLen < 8 || rtLen > len) return false;
    uint32_t present = uint32_t(data[4]) | (uint32_t(data[5]) << 8)
                     | (uint32_t(data[6]) << 16) | (uint32_t(data[7]) << 24);

    size_t off = 8;
    auto alignTo = [&](size_t a) { off = (off + a - 1) & ~(a - 1); };

    // Les champs Radiotap sont optionnels et doivent respecter leur alignement
    // avant que l'on puisse localiser le RSSI.
    if (present & (1u << 0)) { alignTo(8); off += 8; }
    if (present & (1u << 1)) {            off += 1; }
    if (present & (1u << 2)) {            off += 1; }
    if (present & (1u << 3)) { alignTo(2); off += 4; }
    if (present & (1u << 4)) { alignTo(2); off += 2; }
    if (present & (1u << 5)) {
        if (off < rtLen) {
            rssi    = static_cast<int8_t>(data[off]);
            hasRssi = true;
        }
    }
    rtLenOut = rtLen;
    return true;
}

} // namespace

std::optional<Beacon> parseBeacon(const uint8_t* data, size_t len,
                                  uint16_t linkType) {
    bool hasRssi = false;
    int  rssi    = 0;

    if (linkType == pcapng::kLinkTypeRadiotap) {
        size_t rtLen = 0;
        if (!parseRadiotap(data, len, hasRssi, rssi, rtLen))
            return std::nullopt;
        // Le parseur Wi-Fi travaille ensuite sur la trame 802.11 seule.
        data += rtLen;
        len  -= rtLen;
    } else if (linkType != pcapng::kLinkTypeIeee80211) {
        return std::nullopt;
    }

    if (len < 24) return std::nullopt;

    const uint8_t fc0 = data[0];
    const uint8_t type    = (fc0 >> 2) & 0x03;
    const uint8_t subtype = (fc0 >> 4) & 0x0F;
    // Type 0 = gestion et sous-type 8 = beacon dans le champ Frame Control.
    if (type != 0 || subtype != 8) return std::nullopt;

    Beacon b;
    std::memcpy(b.bssid.data(), data + 16, 6);
    b.hasRssi = hasRssi;
    b.rssi    = rssi;

    size_t pos = 24 + 12;
    while (pos + 2 <= len) {
        // Chaque Information Element commence par un identifiant et une
        // longueur ; une longueur incoherente arrete le parcours.
        const uint8_t tag  = data[pos];
        const uint8_t tlen = data[pos + 1];
        pos += 2;
        if (pos + tlen > len) break;

        const uint8_t* v = data + pos;
        if (tag == 0x00) {
            b.ssid.assign(reinterpret_cast<const char*>(v), tlen);
        } else if (tag == 0xDD && tlen >= 4) {
            // L'IE 0xDD contient les trois octets de l'OUI, le type
            // constructeur, puis le payload InfoDrone.
            VendorSpecificIe ie;
            ie.oui[0] = v[0]; ie.oui[1] = v[1]; ie.oui[2] = v[2];
            ie.type   = v[3];
            ie.payload.assign(v + 4, v + tlen);
            b.vendorIes.push_back(std::move(ie));
        }
        pos += tlen;
    }
    return b;
}

} // namespace idp::wlan
