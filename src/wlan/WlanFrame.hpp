#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace idp::wlan {

/**
 * @brief Donnees d'un Information Element specifique a un constructeur.
 *
 * Cet IE est extrait d'un beacon 802.11. L'OUI et le type identifient le
 * protocole constructeur ; le payload contient les donnees a decoder.
 */
struct VendorSpecificIe {
    /// Identifiant de l'organisation sur trois octets.
    std::array<uint8_t, 3> oui{};
    /// Sous-type defini par le constructeur.
    uint8_t type = 0;
    /// Donnees suivant l'OUI et le type.
    std::vector<uint8_t> payload;
};

/**
 * @brief Beacon 802.11 extrait d'une trame capturee.
 *
 * Un beacon est un type particulier de trame de gestion 802.11, emis
 * periodiquement par un point d'acces. Il ne represente donc pas n'importe
 * quelle trame Wi-Fi.
 */
struct Beacon {
    /// Adresse MAC du point d'acces annonce par le beacon.
    std::array<uint8_t, 6> bssid{};
    /// Nom du reseau annonce (SSID).
    std::string ssid;
    /// Indique si le niveau RSSI a ete fourni par un en-tete Radiotap.
    bool hasRssi = false;
    /// Niveau du signal en dBm lorsque hasRssi vaut true.
    int  rssi    = 0;
    /// IE constructeur presents dans le beacon.
    std::vector<VendorSpecificIe> vendorIes;
};

/**
 * @brief Identifie et extrait un beacon a partir d'un paquet capture.
 *
 * Une trame peut etre une trame 802.11 directe ou etre precedee d'un
 * en-tete Radiotap. Les autres types de trames 802.11, ainsi que les autres
 * types de liaison, ne sont pas retournes.
 *
 * @param data Octets du paquet capture.
 * @param len Nombre d'octets disponibles dans data.
 * @param linkType Type de liaison PCAPNG du paquet.
 * @return Le beacon extrait, ou std::nullopt si le paquet n'est pas un beacon
 *         exploitable.
 */
std::optional<Beacon> parseBeacon(const uint8_t* data,
                                  size_t len,
                                  uint16_t linkType);

} // namespace idp::wlan
