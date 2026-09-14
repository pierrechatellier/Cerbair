# infodrone-parser

Parseur InfoDrone (signalement électronique français, arrêté du 27/12/2019)
pour captures pcapng contenant des beacons 802.11 Anafi.

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --config Release --parallel

Avec le générateur Visual Studio (multi-configuration), `CMAKE_BUILD_TYPE` est
ignoré lors de la compilation. Il faut donc préciser `--config Release` à
`cmake --build` ; sinon Visual Studio utilise généralement `Debug` par défaut.

## Exécution

    ./build/Release/infodroneParser /chemin/capture.pcapng

## Tests

    ctest --test-dir build --output-on-failure

## Structure

- `src/common/` — lecture binaire endianness-aware
- `src/pcapng/` — lecteur pcapng minimal (SHB/IDB/EPB/SPB)
- `src/wlan/` — parseur de beacons 802.11 + radiotap
- `src/infodrone/` — décodeur TLV InfoDrone
- `tests/` — tests unitaires Catch2

## Vocabulaire du parseur

- Une **frame** (trame) est une unité générale du protocole 802.11 : beacon,
  requête de sondage, acquittement, trame de données, etc.
- Un **beacon** est un type particulier de frame de gestion 802.11. Il est
  émis périodiquement pour annoncer un réseau Wi-Fi et ses Information
  Elements (IE).
- **Radiotap** est un en-tête de métadonnées de capture qui peut précéder une
  frame 802.11 ; ce n'est pas un beacon.
- `wlan::Beacon` représente le beacon Wi-Fi extrait, tandis que
  `infodrone::Frame` représente les données InfoDrone décodées depuis un IE
  constructeur de ce beacon. Ce sont donc deux niveaux différents :

      [Radiotap éventuel][frame 802.11, éventuellement un beacon]
                                      -> [IE constructeur]
                                      -> [Frame InfoDrone]
