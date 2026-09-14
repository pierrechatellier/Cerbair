#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace idp::wlan {

struct VendorSpecificIe {
    std::array<uint8_t, 3> oui{};
    uint8_t type = 0;
    std::vector<uint8_t> payload;
};

struct Beacon {
    std::array<uint8_t, 6> bssid{};
    std::string ssid;
    bool hasRssi = false;
    int  rssi    = 0;
    std::vector<VendorSpecificIe> vendorIes;
};

std::optional<Beacon> parseBeacon(const uint8_t* data,
                                  size_t len,
                                  uint16_t linkType);

} // namespace idp::wlan
