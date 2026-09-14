#pragma once
#include "wlan/WlanFrame.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace idp::infodrone {

constexpr uint8_t kOui[3] = {0x6A, 0x5C, 0x35};
constexpr uint8_t kVendorType = 0x01;

/**
 * @brief Donnees InfoDrone decodees depuis le payload d'un IE constructeur.
 *
 * Cette structure represente le contenu metier du message InfoDrone, et non
 * la trame Wi-Fi qui le transporte. Les anomalies de format sont conservees
 * dans warnings plutot que de modifier la trame 802.11.
 */
struct Frame {
    /// Version du format InfoDrone.
    int         version        = 0;
    /// Identifiant FR-30.
    std::string frId;
    /// Identifiant ANSI/CTA-2063.
    std::string ansiId;
    /// Latitude de la position courante en degres decimaux.
    double      latitude       = 0.0;
    /// Longitude de la position courante en degres decimaux.
    double      longitude      = 0.0;
    /// Altitude au-dessus du niveau moyen de la mer, en metres.
    double      altitudeAmslM  = 0.0;
    /// Hauteur au-dessus du sol, en metres.
    double      heightAglM     = 0.0;
    /// Latitude du point de decollage en degres decimaux.
    double      takeoffLat     = 0.0;
    /// Longitude du point de decollage en degres decimaux.
    double      takeoffLon     = 0.0;
    /// Vitesse sol, en metres par seconde.
    double      groundSpeedMps = 0.0;
    /// Cap vrai, en degres.
    double      trueCourseDeg  = 0.0;
    /// Avertissements produits pendant le decodage des TLV.
    std::vector<std::string> warnings;
};

/**
 * @brief Verifie si un IE constructeur est un message InfoDrone.
 * @param ie IE extrait d'un beacon 802.11.
 * @return true si l'OUI et le type correspondent au protocole InfoDrone.
 */
bool isInfoDrone(const wlan::VendorSpecificIe& ie);

/**
 * @brief Decode les TLV du payload d'un IE InfoDrone.
 * @param ie IE constructeur identifie par isInfoDrone().
 * @return Les champs InfoDrone et les avertissements eventuels.
 */
Frame decode(const wlan::VendorSpecificIe& ie);

} // namespace idp::infodrone
