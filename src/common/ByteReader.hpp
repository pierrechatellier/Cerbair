#pragma once
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace idp {
/**
 * @brief Erreur levee lorsqu'une donnee binaire est invalide ou incomplete.
 */
class ParseError : public std::runtime_error {
   public:
    /**
     * @param m Message detaille de l'erreur.
     */
    explicit ParseError(const std::string& m) : std::runtime_error(m) {}
};

/**
 * @brief Lecteur sequentiel d'entiers et de blocs d'octets.
 *
 * Le lecteur verifie chaque acces et leve ParseError lorsqu'il depasse la zone fournie. Les entiers
 * sont lus dans l'endianness indiquee a la creation.
 */
class ByteReader {
   public:
    /**
     * @param data Debut de la zone memoire a lire.
     * @param size Taille de la zone memoire en octets.
     * @param littleEndian true pour le little-endian, false pour le big-endian.
     */
    ByteReader(const uint8_t* data, size_t size, bool littleEndian)
        : data_(data), size_(size), le_(littleEndian) {}

    /// Retourne le nombre d'octets qui restent a lire.
    size_t remaining() const { return size_ - pos_; }
    /// Retourne la position courante en octets depuis le debut.
    size_t position() const { return pos_; }
    /// Indique si les entiers sont lus en little-endian.
    bool littleEndian() const { return le_; }

    /// Lit un entier non signe sur 1 octet.
    uint8_t u8() { return readInt<uint8_t>(1); }
    /// Lit un entier non signe sur 2 octets.
    uint16_t u16() { return readInt<uint16_t>(2); }
    /// Lit un entier non signe sur 4 octets.
    uint32_t u32() { return readInt<uint32_t>(4); }
    /// Lit un entier non signe sur 8 octets.
    uint64_t u64() { return readInt<uint64_t>(8); }
    /// Lit un entier signe sur 4 octets.
    int32_t i32() { return static_cast<int32_t>(u32()); }

    /**
     * @brief Retourne un bloc d'octets et avance la position.
     * @param n Nombre d'octets a lire.
     * @return Pointeur vers le debut du bloc lu.
     */
    const uint8_t* bytes(size_t n) {
        require(n);
        const uint8_t* p = data_ + pos_;
        pos_ += n;
        return p;
    }
    /// Ignore n octets apres verification de leur disponibilite.
    void skip(size_t n) {
        require(n);
        pos_ += n;
    }

   private:
    template <typename T>
    T readInt(std::size_t n) {
        // La construction octet par octet evite de dependre de l'architecture de la machine qui
        // execute le parseur.
        require(n);
        T v = 0;
        if (le_) {
            for (std::size_t i = 0; i < n; ++i) v |= static_cast<T>(data_[pos_ + i]) << (8 * i);
        } else {
            for (std::size_t i = 0; i < n; ++i) v = static_cast<T>((v << 8) | data_[pos_ + i]);
        }
        pos_ += n;
        return v;
    }
    void require(std::size_t n) const {
        // Toutes les lectures passent par ce garde-fou avant d'avancer pos_.
        if (pos_ + n > size_) throw ParseError("ByteReader: out-of-bounds read");
    }

    const uint8_t* data_;
    std::size_t size_;
    std::size_t pos_ = 0;
    bool le_;
};

}  // namespace idp
