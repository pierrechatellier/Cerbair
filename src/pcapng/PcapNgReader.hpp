#pragma once
#include <cstdint>
#include <fstream>
#include <istream>
#include <string>
#include <vector>

#include "common/ByteReader.hpp"

namespace idp::pcapng {

/// Types de blocs PCAPNG pris en compte par le lecteur.
constexpr uint32_t kSectionHeaderBlock = 0x0A0D0D0A;
constexpr uint32_t kInterfaceDescriptionBlock = 0x00000001;
constexpr uint32_t kPacketBlock = 0x00000002;
constexpr uint32_t kSimplePacketBlock = 0x00000003;
constexpr uint32_t kNameResolutionBlock = 0x00000004;
constexpr uint32_t kInterfaceStatisticsBlock = 0x00000005;
constexpr uint32_t kEnhancedPacketBlock = 0x00000006;

/// Types de liaison utilises par les captures supportees.
constexpr uint16_t kLinkTypeEthernet = 1;
constexpr uint16_t kLinkTypeIeee80211 = 105;
constexpr uint16_t kLinkTypeRadiotap = 127;

/**
 * @brief Paquet extrait d'un bloc de donnees PCAPNG.
 */
struct Packet {
    /// Identifiant de l'interface de capture.
    uint32_t interfaceId = 0;
    /// Horodatage du paquet en nanosecondes.
    uint64_t timestampNs = 0;
    /// Type de liaison de l'interface (Ethernet, 802.11 ou Radiotap).
    uint16_t linkType = 0;
    /// Octets bruts du paquet capture.
    std::vector<uint8_t> data;
};

/**
 * @brief Lecteur minimal de fichiers PCAPNG.
 *
 * Le lecteur traite les blocs SHB, IDB, EPB et SPB, ignore les autres blocs et fournit un paquet a
 * la fois via next().
 */
class PcapNgReader {
   public:
    /**
     * @brief Construit un lecteur sur un flux deja ouvert.
     * @param in Flux binaire contenant un fichier PCAPNG.
     */
    explicit PcapNgReader(std::istream& in) : in_(&in) {}

    /**
     * @brief Construit un lecteur et ouvre un fichier PCAPNG.
     * @param path Chemin du fichier a ouvrir.
     * @throws std::runtime_error si le fichier ne peut pas etre ouvert.
     */
    explicit PcapNgReader(const std::string& path) : file_(path, std::ios::binary) {
        if (!file_) throw std::runtime_error("Cannot open pcapng: " + path);
        in_ = &file_;
    }

    /**
     * @brief Lit le prochain paquet capture.
     * @param[out] out Objet rempli avec les metadonnees et les octets du paquet.
     * @return false en fin de fichier, true lorsqu'un paquet a ete extrait.
     * @throws ParseError si la structure PCAPNG est tronquee ou invalide.
     */
    bool next(Packet& out);

    /// Retourne les types de liaison declares par les blocs IDB.
    const std::vector<uint16_t>& interfaceLinkTypes() const { return linkTypes_; }

   private:
    void readExact(void* dst, size_t n, const char* what);

    std::ifstream file_;
    std::istream* in_ = nullptr;
    bool littleEndian_ = true;
    bool byteOrderSeen_ = false;
    std::vector<uint16_t> linkTypes_;
};

}  // namespace idp::pcapng
