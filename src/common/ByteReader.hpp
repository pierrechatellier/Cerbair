#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <string>

namespace idp {

class ParseError : public std::runtime_error {
public:
    explicit ParseError(const std::string& m) : std::runtime_error(m) {}
};

class ByteReader {
public:
    ByteReader(const uint8_t* data, size_t size, bool littleEndian)
        : data_(data), size_(size), le_(littleEndian) {}

    size_t remaining() const { return size_ - pos_; }
    size_t position()  const { return pos_; }
    bool   littleEndian() const { return le_; }

    uint8_t  u8 () { return readInt<uint8_t >(1); }
    uint16_t u16() { return readInt<uint16_t>(2); }
    uint32_t u32() { return readInt<uint32_t>(4); }
    uint64_t u64() { return readInt<uint64_t>(8); }
    int32_t  i32() { return static_cast<int32_t>(u32()); }

    const uint8_t* bytes(size_t n) {
        require(n);
        const uint8_t* p = data_ + pos_;
        pos_ += n;
        return p;
    }
    void skip(size_t n) { require(n); pos_ += n; }

private:
    template <typename T>
    T readInt(size_t n) {
        require(n);
        T v = 0;
        if (le_) {
            for (size_t i = 0; i < n; ++i)
                v |= static_cast<T>(data_[pos_ + i]) << (8 * i);
        } else {
            for (size_t i = 0; i < n; ++i)
                v = static_cast<T>((v << 8) | data_[pos_ + i]);
        }
        pos_ += n;
        return v;
    }
    void require(size_t n) const {
        if (pos_ + n > size_)
            throw ParseError("ByteReader: out-of-bounds read");
    }

    const uint8_t* data_;
    size_t size_;
    size_t pos_ = 0;
    bool   le_;
};

} // namespace idp
