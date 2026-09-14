#pragma once
#include "wlan/WlanFrame.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace idp::infodrone {

constexpr uint8_t kOui[3] = {0x6A, 0x5C, 0x35};
constexpr uint8_t kVendorType = 0x01;

struct Frame {
    int         version        = 0;
    std::string frId;
    std::string ansiId;
    double      latitude       = 0.0;
    double      longitude      = 0.0;
    double      altitudeAmslM  = 0.0;
    double      heightAglM     = 0.0;
    double      takeoffLat     = 0.0;
    double      takeoffLon     = 0.0;
    double      groundSpeedMps = 0.0;
    double      trueCourseDeg  = 0.0;
    std::vector<std::string> warnings;
};

bool isInfoDrone(const wlan::VendorSpecificIe& ie);
Frame decode(const wlan::VendorSpecificIe& ie);

} // namespace idp::infodrone
