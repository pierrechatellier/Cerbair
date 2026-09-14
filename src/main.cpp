#include "pcapng/PcapNgReader.hpp"
#include "wlan/WlanFrame.hpp"
#include "infodrone/InfoDroneDecoder.hpp"

#include <cstdio>
#include <iomanip>
#include <iostream>

using namespace idp;

static void printFrame(const infodrone::Frame& f,
                       const wlan::Beacon& b,
                       uint64_t tsNs)
{
    std::cout << "--- InfoDrone ---\n";
    std::cout << "  timestamp_ns : " << tsNs << "\n";
    std::cout << "  BSSID        : ";
    for (size_t i = 0; i < b.bssid.size(); ++i)
        std::printf("%02X%s", b.bssid[i], i + 1 < b.bssid.size() ? ":" : "");
    std::cout << "\n";
    std::cout << "  SSID         : " << b.ssid << "\n";
    if (b.hasRssi)
        std::cout << "  RSSI         : " << b.rssi << " dBm\n";
    std::cout << "  version      : " << f.version << "\n";
    std::cout << "  FR-30        : " << f.frId << "\n";
    std::cout << "  ANSI/CTA-2063: " << f.ansiId << "\n";
    std::cout << std::fixed << std::setprecision(5)
              << "  position     : " << f.latitude << ", " << f.longitude << "\n"
              << std::setprecision(1)
              << "  altitude AMSL: " << f.altitudeAmslM << " m\n"
              << "  height AGL   : " << f.heightAglM    << " m\n"
              << "  takeoff      : " << f.takeoffLat << ", " << f.takeoffLon << "\n"
              << "  ground speed : " << f.groundSpeedMps << " m/s\n"
              << "  true course  : " << f.trueCourseDeg  << " deg\n";
    for (const auto& w : f.warnings)
        std::cout << "  [warn] " << w << "\n";
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file.pcapng>\n";
        return 1;
    }

    try {
        pcapng::PcapNgReader reader(argv[1]);
        pcapng::Packet pkt;
        size_t seen = 0, beacons = 0, idFrames = 0;

        while (reader.next(pkt)) {
            ++seen;
            auto beacon = wlan::parseBeacon(pkt.data.data(),
                                            pkt.data.size(),
                                            pkt.linkType);
            if (!beacon) continue;
            ++beacons;
            for (const auto& ie : beacon->vendorIes) {
                if (!infodrone::isInfoDrone(ie)) continue;
                auto f = infodrone::decode(ie);
                printFrame(f, *beacon, pkt.timestampNs);
                ++idFrames;
            }
        }
        std::cout << "\nPackets read: " << seen
                  << "  beacons: "     << beacons
                  << "  InfoDrone: "   << idFrames << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    }
}
