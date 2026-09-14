# Rapport technique — parseur InfoDrone

## 1. Objet et périmètre

Le projet est un parseur C++17 qui extrait des signalements InfoDrone présents
dans des beacons IEEE 802.11, à partir d'une capture `.pcapng`. Le chemin
nominal est le suivant :

```text
pcapng (SHB/IDB/EPB/SPB)
    -> trame 802.11 ou radiotap + 802.11
    -> beacon et Information Elements (IE)
    -> IE constructeur (OUI 6A:5C:35, type 0x01)
    -> TLV InfoDrone
    -> affichage d'un Frame et de ses avertissements
```

Le périmètre implémenté est volontairement ciblé sur les beacons Anafi et le
format InfoDrone couvert par le décodeur actuel. Il ne s'agit pas encore d'un
collecteur radio généraliste ni d'une implémentation exhaustive de toutes les
variantes de signalement.

## 2. Documentation utilisée

### 2.1 Sources et spécifications consultées

Les références utilisées pour concevoir et vérifier le lecteur sont :

* **Arrêté français du 27 décembre 2019 relatif au signalement électronique
  des aéronefs sans équipage à bord**, qui constitue le contexte réglementaire
  du format InfoDrone et de l'identification FR-30.
  [Legifrance — texte de l'arrêté](https://www.legifrance.gouv.fr/jorf/id/JORFTEXT000039684195)
* **Projet de spécification pcapng de l'IETF/OPSAWG**, utilisé pour la
  structure des Section Header Blocks, le marqueur d'endianness, les longueurs
  de blocs et les Enhanced Packet Blocks.
  [IETF Datatracker — pcapng](https://datatracker.ietf.org/doc/draft-tuexen-opsawg-pcapng/)
* **Présentation technique pcapng**, utile comme référence lisible pour les
  SHB, IDB, EPB et le support de plusieurs link-types dans une même capture.
  [pcapng.com](https://pcapng.com/)
* **Registres IEEE 802/IANA**, notamment pour les valeurs de link-layer
  utilisées par le projet : IEEE 802.11 (`105`) et radiotap (`127`).
  [IANA — IEEE 802 Numbers](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)

Le dépôt ne contient pas de copie locale d'une spécification propriétaire
InfoDrone ni de schéma versionné séparément. Les constantes et champs
effectivement supportés sont donc ceux explicités par le code et les tests :
OUI `6A:5C:35`, type constructeur `0x01`, puis les TLV `0x01` à `0x0B`.
Cette liste devra être rapprochée d'une spécification officielle ou d'un jeu
de captures de conformité avant une mise en production réglementaire.

### 2.2 Outils et bibliothèques pcapng

Le lecteur pcapng est implémenté en interne dans
[`src/pcapng/PcapNgReader.cpp`](C:/Users/pierr/Downloads/infodrone-parser/src/pcapng/PcapNgReader.cpp)
; le projet n'utilise donc ni libpcap ni libwiretap à l'exécution.
[`src/common/ByteReader.hpp`](C:/Users/pierr/Downloads/infodrone-parser/src/common/ByteReader.hpp)
fournit une lecture bornée et sensible à l'endianness.

La seule dépendance externe de développement est Catch2 `v3.5.2`, récupérée
par `FetchContent` dans
[`CMakeLists.txt`](C:/Users/pierr/Downloads/infodrone-parser/CMakeLists.txt)
pour les tests unitaires. Elle n'est pas nécessaire au binaire livré.

## 3. Choix d'architecture

### 3.1 Structure générale et patterns

Le code est organisé en couches, chacune manipulant un type de donnée explicite :

* `common` : primitives de lecture binaire (`ByteReader`, `ParseError`) ;
* `pcapng` : lecture séquentielle du conteneur et production d'un `Packet`
  `{interfaceId, timestampNs, linkType, data}` ;
* `wlan` : suppression optionnelle du radiotap, validation du type beacon,
  extraction du BSSID, SSID et des IE constructeur ;
* `infodrone` : filtrage par OUI/type puis décodage TLV vers `Frame` ;
* `main` : orchestration, statistiques et rendu texte.

Les choix principaux sont :

* **pipeline séquentiel** : `PcapNgReader::next` évite de charger toute la
  capture en mémoire et convient aux gros fichiers ;
* **types valeur et `std::optional`** : une trame qui n'est pas un beacon ou
  n'a pas le link-type attendu est ignorée sans exception ;
* **exceptions seulement pour les erreurs structurelles** : un fichier
  illisible ou incohérent lève `ParseError`, tandis qu'un champ TLV invalide
  produit un avertissement attaché au `Frame` ;
* **bibliothèque statique `infodrone_core`** : le cœur est découplé de
  l'interface CLI et peut être réutilisé par un service ou des tests ;
* **tests unitaires Catch2** sur la lecture binaire, pcapng, beacon et TLV.

Une alternative aurait été de déléguer pcapng et 802.11 à libpcap/libwiretap.
Cela aurait augmenté la couverture des variantes pcapng, mais aussi la surface
de dépendances, la complexité du packaging et la dépendance à une API externe.
Pour un parseur de démonstration au format restreint, le lecteur minimal
explicite est plus facile à auditer ; pour un produit multi-captures, libpcap
ou libwiretap deviendrait néanmoins une option à réévaluer.

### 3.2 Passage à une capture live

Le cœur ne dépend déjà pas du système de fichiers : `PcapNgReader` accepte
également un `std::istream`. La prochaine étape serait de formaliser cette
séparation par une petite interface de source, par exemple :

```cpp
class PacketSource {
public:
    virtual ~PacketSource() = default;
    virtual bool next(pcapng::Packet& packet) = 0;
};
```

`PcapNgSource` encapsulerait le lecteur actuel et `LiveWifiSource` utiliserait
une bibliothèque/capture native (par exemple libpcap en mode monitor) pour
remplir le même `Packet`. Les couches `wlan` et `infodrone` resteraient
inchangées ; seul le câblage de `main` et la gestion de l'arrêt/du timeout
seraient ajoutés.

### 3.3 Ajout de Bluetooth, 4G ou autres signalements

Le contrat à stabiliser serait un événement normalisé contenant au minimum
un timestamp, une source radio, une identité et un signalement décodé. La
source fournirait des paquets bruts, puis un registre de décodeurs
sélectionnerait un décodeur par link-type, protocole ou préfixe :

```text
PacketSource -> FrameDetector -> SignalDecoder -> NormalizedReport -> Renderer
```

Le décodeur InfoDrone actuel deviendrait un `SignalDecoder` parmi d'autres.
Un `BluetoothDecoder` ou un `CellularDecoder` pourrait être ajouté dans un
nouveau module sans modifier le lecteur pcapng ni les TLV existants. Cette
évolution nécessite une extraction modérée de l'orchestration actuellement
dans `main`, mais pas de refactorisation du parsing bas niveau.

## 4. Robustesse et gestion des erreurs

La stratégie distingue les erreurs qui rendent la suite impossible des
irrégularités locales :

* **fichier introuvable ou lecture courte** : exception explicite (`Cannot
  open pcapng`, `short read`) ; le CLI affiche l'erreur et retourne `2` ;
* **pcapng invalide** : contrôle du SHB, du byte-order magic, des longueurs
  minimales, de l'alignement, du trailer de longueur et de la présence d'un
  SHB avant les autres blocs ;
* **bloc inconnu** : consommé et ignoré après validation de sa longueur, ce
  qui permet l'extensibilité pcapng ;
* **interface inconnue dans un EPB** : le paquet est conservé mais reçoit un
  `linkType` nul et n'est pas interprété comme du Wi-Fi ;
* **trame trop courte ou mauvais type 802.11** : `std::nullopt`, sans arrêt de
  la capture ;
* **IE tronqué** : arrêt du parcours des IE, sans lecture hors limites ;
* **TLV manquant, inconnu ou de longueur inattendue** : valeurs par défaut
  conservées et message dans `Frame::warnings`, afin de produire le maximum
  d'information sans inventer une valeur ;
* **capture mixte** : les link-types sont mémorisés par interface, ce qui
  permet de sauter proprement les paquets Ethernet ou autres.

Pour durcir encore le comportement, il faudrait ajouter des limites explicites
sur les tailles de bloc/paquet avant allocation, vérifier les options pcapng,
gérer les sections multiples avec leur propre table d'interfaces et ajouter
des tests de fuzzing sur les octets d'entrée. Il serait également préférable
de retourner une erreur contextualisée avec offset de bloc et numéro de paquet.

## 5. Packaging et dépendances

### 5.1 État actuel

Le dépôt ne contient actuellement ni fichier `debian/`, ni configuration
CPack, ni cible de packaging `.deb`. Le binaire de production est lié à la
bibliothèque statique interne `infodrone_core`. Catch2 est une dépendance de
tests seulement et ne doit pas être embarqué dans le paquet runtime.

### 5.2 Solution retenue pour le `.deb`

La solution recommandée est **CPack DEB piloté par CMake**, avec :

* `infodrone_core` statique dans l'exécutable ;
* dépendances système dynamiques normales (`libstdc++6`, `libgcc-s1`,
  `libc6`) déclarées par le paquet, plutôt qu'un faux static linking de toute
  la libc ;
* Catch2 exclu du paquet final ;
* installation de `infodroneParser` dans `/usr/bin` et d'une page de manuel ou
  d'un README dans `/usr/share/doc/infodrone-parser/` ;
* version, architecture et description définies à partir des variables CMake.

Cette approche évite de vendoriser des bibliothèques système et s'intègre au
cycle CMake déjà présent. Un paquet Debian natif (`debian/rules`) serait
préférable si le projet devait intégrer les conventions Debian complètes,
les symboles de debug et les builds reproductibles ; CPack est plus
proportionné au projet actuel.

### 5.3 Commandes de reproduction

Sur une machine Debian/Ubuntu équipée de `cmake`, `ninja` ou `make`, `g++` et
des outils de packaging :

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
  -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build --prefix /usr --strip
cpack --config build/CPackConfig.cmake -G DEB
```

Dans l'état actuel, la dernière commande ne peut pas encore réussir car la
configuration CPack et les règles `install()` restent à ajouter. La première
étape d'implémentation serait donc d'ajouter ces règles à
[`CMakeLists.txt`](C:/Users/pierr/Downloads/infodrone-parser/CMakeLists.txt),
puis de construire dans un environnement Debian propre et de vérifier le
contenu avec `dpkg-deb --info` et `dpkg-deb --contents`.

Pour un build reproductible, il faudrait également figer le générateur,
l'architecture cible, le compilateur et la provenance de Catch2 (miroir ou
archive avec hash), plutôt que dépendre uniquement d'un clone Git distant
via `FetchContent`.

## 6. Limites connues et perspectives

### 6.1 Limites identifiées

* Le décodage est limité au format InfoDrone et à l'OUI/type codés dans le
  projet ; les autres fabricants, versions ou variantes de signalement ne
  sont pas décodés.
* Seuls les beacons 802.11 sont recherchés. Les probe responses, trames
  fragmentées, encapsulations non radiotap et formats radio spécifiques ne
  sont pas couverts de manière générale.
* Le parsing radiotap ne traite qu'un sous-ensemble du bitmap de présence et
  ne gère pas les bitmaps étendus ; le RSSI est donc optionnel.
* Les timestamps sont exposés comme des nanosecondes sans interprétation des
  unités configurées par l'option pcapng de l'interface.
* Les options, commentaires, statistiques d'interface et certains blocs
  pcapng sont ignorés.
* Le rendu est uniquement textuel et le programme ne propose ni JSON, ni
  sortie machine stable, ni agrégation/déduplication des annonces.
* Les champs géographiques et physiques sont peu validés : absence de
  contrôle de plage, de cohérence entre champs ou de vérification de version.
* Le CLI traite une erreur structurelle comme une erreur fatale ; un mode
  « best effort » permettant de continuer après un bloc corrompu n'existe pas.

### 6.2 Ce qui aurait été ajouté avec plus de temps

Les priorités seraient :

1. obtenir un corpus de captures réelles annotées et une spécification
   InfoDrone versionnée ;
2. ajouter tests de conformité, tests de non-régression, fuzzing et mesures
   de couverture ;
3. extraire `PacketSource`, ajouter la capture live monitor-mode et une
   terminaison propre ;
4. compléter radiotap et pcapng (options, sections multiples, unités de temps,
   tailles bornées) ;
5. fournir JSON/CSV, filtrage, déduplication et logs structurés ;
6. ajouter CPack/CI Debian et un build reproductible ;
7. introduire un modèle de signalement commun et des plugins Bluetooth/4G.

La validation actuelle du build déjà présent montre 13 tests passants sur 15.
Deux tests existants échouent : `ByteReader little-endian` attend une valeur
qui ne correspond pas aux octets réellement consommés après `u8()` et `u16()`,
et `pcapng: corrupted length trailer throws` ne déclenche pas l'exception
attendue. Ces échecs doivent être corrigés ou clarifiés avant de considérer
la CI comme verte ; ils ne doivent pas être masqués par le rapport.

## 7. Vision lead : organisation en équipe

J'organiserais le projet autour de contrats d'entrée/sortie et d'un corpus de
référence partagé :

* **Référent protocole/réglementaire** : spécifications, versions, champs,
  compatibilité et validation des captures ;
* **Équipe ingestion** : pcapng, libpcap/live capture, radiotap, limites et
  performance ;
* **Équipe décodage** : modèle normalisé, InfoDrone, puis Bluetooth/4G ;
* **Équipe produit/CLI** : formats de sortie, UX, logs, filtres et
  déduplication ;
* **Équipe qualité/packaging** : tests de conformité, fuzzing, CI, CPack,
  `.deb`, reproductibilité et documentation.

Chaque changement de protocole devrait être accompagné d'une capture
minimale, d'un test positif et d'un test négatif. Les interfaces entre
équipes seraient des types C++ stables (`Packet`, événement radio,
`NormalizedReport`) et non des dépendances aux structures internes d'un
décodeur.

Le flux de livraison serait : revue de spécification, implémentation isolée,
tests unitaires et corpus, fuzzing ciblé, revue de sécurité/robustesse, build
multi-plateforme, puis publication d'un paquet versionné. Une CI devrait
exécuter au minimum compilation stricte, tests Catch2, analyse statique,
sanitizers sur Linux, test de reconstruction du `.deb` et validation de son
contenu. Cette organisation permettrait d'ajouter une source live ou un
nouveau protocole sans faire dépendre toute l'équipe des détails du lecteur
pcapng actuel.
