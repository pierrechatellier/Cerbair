# infodrone-parser

Parseur InfoDrone (signalement électronique français, arrêté du 27/12/2019)
pour captures pcapng contenant des beacons 802.11 Anafi.

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j

## Exécution

    ./build/infodroneParser /chemin/capture.pcapng

## Tests

    ctest --test-dir build --output-on-failure

## Structure

- `src/common/` — lecture binaire endianness-aware
- `src/pcapng/` — lecteur pcapng minimal (SHB/IDB/EPB/SPB)
- `src/wlan/` — parseur de beacons 802.11 + radiotap
- `src/infodrone/` — décodeur TLV InfoDrone
- `tests/` — tests unitaires Catch2
