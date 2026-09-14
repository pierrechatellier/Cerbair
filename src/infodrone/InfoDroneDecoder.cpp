#include "infodrone/InfoDroneDecoder.hpp"

#include "common/ByteReader.hpp"

namespace idp::infodrone {

bool isInfoDrone(const wlan::VendorSpecificIe& ie) {
    // L'OUI et le type forment la signature de l'IE constructeur InfoDrone.
    return ie.oui[0] == kOui[0] && ie.oui[1] == kOui[1] && ie.oui[2] == kOui[2] &&
           ie.type == kVendorType;
}

namespace {
void decodeTlv(Frame& f, uint8_t type, const uint8_t* v, uint8_t len) {
    ByteReader r(v, len, /*littleEndian=*/true);

    // Chaque type possede une longueur attendue ; une longueur incorrecte produit un avertissement
    // sans interrompre le decodage des autres TLV.
    switch (type) {
        case 0x01:
            if (len == 1)
                f.version = r.u8();
            else
                f.warnings.push_back("version: bad length");
            break;
        case 0x02:
            f.frId.assign(reinterpret_cast<const char*>(v), len);
            break;
        case 0x03:
            f.ansiId.assign(reinterpret_cast<const char*>(v), len);
            break;
        case 0x04:
            if (len == 4)
                f.latitude = r.i32() / 1e5;
            else
                f.warnings.push_back("latitude: expected 4 bytes");
            break;
        case 0x05:
            if (len == 4)
                f.longitude = r.i32() / 1e5;
            else
                f.warnings.push_back("longitude: expected 4 bytes");
            break;
        case 0x06:
            if (len == 2)
                f.altitudeAmslM = r.u16();
            else if (len == 4)
                f.altitudeAmslM = r.u32();
            else
                f.warnings.push_back("altitude AMSL: unexpected length");
            break;
        case 0x07:
            if (len == 2)
                f.heightAglM = r.u16();
            else if (len == 4)
                f.heightAglM = r.u32();
            else
                f.warnings.push_back("height AGL: unexpected length");
            break;
        case 0x08:
            if (len == 4)
                f.takeoffLat = r.i32() / 1e5;
            else
                f.warnings.push_back("takeoff lat: expected 4 bytes");
            break;
        case 0x09:
            if (len == 4)
                f.takeoffLon = r.i32() / 1e5;
            else
                f.warnings.push_back("takeoff lon: expected 4 bytes");
            break;
        case 0x0A:
            if (len == 2)
                f.groundSpeedMps = r.u16() / 10.0;
            else
                f.warnings.push_back("ground speed: expected 2 bytes");
            break;
        case 0x0B:
            if (len == 2)
                f.trueCourseDeg = r.u16() / 10.0;
            else
                f.warnings.push_back("true course: expected 2 bytes");
            break;
        default:
            f.warnings.push_back("unknown TLV 0x" + std::to_string(static_cast<int>(type)));
            break;
    }
}
}  // namespace

Frame decode(const wlan::VendorSpecificIe& ie) {
    Frame f;
    const uint8_t* p = ie.payload.data();
    std::size_t n = ie.payload.size();
    std::size_t i = 0;

    while (i + 2 <= n) {
        // Le payload est une suite [type][longueur][valeur]. La verification avant decode evite
        // toute lecture au-dela du payload capture.
        const uint8_t t = p[i];
        const uint8_t len = p[i + 1];
        i += 2;

        if (i + len > n) {
            f.warnings.push_back("TLV truncated at offset " + std::to_string(i));
            break;
        }

        decodeTlv(f, t, p + i, len);
        i += len;
    }

    if (i != n) f.warnings.push_back("trailing bytes after last TLV");
    return f;
}

}  // namespace idp::infodrone
