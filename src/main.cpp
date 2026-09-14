#include <cstdio>
#include <iomanip>
#include <iostream>

#include "infodrone/InfoDroneDecoder.hpp"
#include "pcapng/PcapNgReader.hpp"
#include "wlan/WlanFrame.hpp"

using namespace idp;

/**
 * @brief Affiche une trame InfoDrone et les metadonnees de son beacon Wi-Fi.
 * @param f Donnees InfoDrone decodees depuis l'IE constructeur.
 * @param b Beacon 802.11 qui transportait l'IE.
 * @param tsNs Horodatage de capture en nanosecondes.
 */
static void printFrame(const infodrone::Frame& f, const wlan::Beacon& b, const uint64_t tsNs) {
    std::cout << "--- InfoDrone ---\n";
    std::cout << "  timestamp_ns : " << tsNs << "\n";
    std::cout << "  BSSID        : ";
    for (std::size_t i = 0; i < b.bssid.size(); ++i)
        std::printf("%02X%s", b.bssid[i], i + 1 < b.bssid.size() ? ":" : "");
    std::cout << "\n";
    std::cout << "  SSID         : " << b.ssid << "\n";
    if (b.hasRssi) std::cout << "  RSSI         : " << b.rssi << " dBm\n";
    std::cout << "  version      : " << f.version << "\n";
    std::cout << "  FR-30        : " << f.frId << "\n";
    std::cout << "  ANSI/CTA-2063: " << f.ansiId << "\n";
    std::cout << std::fixed << std::setprecision(5) << "  position     : " << f.latitude << ", "
              << f.longitude << "\n"
              << std::setprecision(1) << "  altitude AMSL: " << f.altitudeAmslM << " m\n"
              << "  height AGL   : " << f.heightAglM << " m\n"
              << "  takeoff      : " << f.takeoffLat << ", " << f.takeoffLon << "\n"
              << "  ground speed : " << f.groundSpeedMps << " m/s\n"
              << "  true course  : " << f.trueCourseDeg << " deg\n";
    for (const auto& w : f.warnings) std::cout << "  [warn] " << w << "\n";
}

/**
 * @brief Point d'entree du parseur de captures PCAPNG.
 *
 * Le programme extrait les beacons 802.11, recherche les IE constructeur InfoDrone, decode leurs
 * TLV puis affiche les trames reconnues.
 *
 * @param argc Nombre d'arguments de la ligne de commande.
 * @param argv Arguments ; argv[1] doit contenir le chemin d'un fichier PCAPNG.
 * @return 0 en cas de succes, 1 si les arguments sont invalides, 2 en cas d'erreur de lecture ou de
 * decodage.
 */
int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file.pcapng>\n";
        return 1;
    }

    try {
        // Le lecteur masque les details des blocs PCAPNG et fournit un paquet complet a chaque
        // appel a next().
        pcapng::PcapNgReader reader(argv[1]);
        pcapng::Packet pkt;
        std::size_t seen = 0;
        std::size_t beacons = 0;
        std::size_t idFrames = 0;

        while (reader.next(pkt)) {
            ++seen;
            // Une trame Ethernet ou une trame 802.11 non-beacon est ignoree avant toute recherche
            // de donnees constructeur.
            auto beacon = wlan::parseBeacon(pkt.data.data(), pkt.data.size(), pkt.linkType);

            if (!beacon) continue;
            ++beacons;

            // Un beacon peut contenir plusieurs IE constructeur ; seul celui dont l'OUI et le type
            // correspondent est decode en InfoDrone.
            for (const auto& ie : beacon->vendorIes) {
                if (!infodrone::isInfoDrone(ie)) continue;
                auto f = infodrone::decode(ie);
                printFrame(f, *beacon, pkt.timestampNs);
                ++idFrames;
            }
        }

        std::cout << "\nPackets read: " << seen << "  beacons: " << beacons
                  << "  InfoDrone: " << idFrames << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    }
}
