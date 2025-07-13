#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <sstream>
#include <iomanip>
class CryptoUtils {
public:
    static std::string sha256(const uint8_t* data, size_t length);
    static std::string md5(const uint8_t* data, size_t length);
    static std::string sha1(const uint8_t* data, size_t length);
private:
    static const uint32_t K[64];
    static uint32_t rotr(uint32_t x, int n);
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t sig0(uint32_t x);
    static uint32_t sig1(uint32_t x);
    static uint32_t Sig0(uint32_t x);
    static uint32_t Sig1(uint32_t x);
    static const uint32_t MD5_K[64];
    static uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t md5_rotleft(uint32_t value, int amount);
    static uint32_t sha1_rotleft(uint32_t value, int amount);
    static uint32_t sha1_f(int t, uint32_t b, uint32_t c, uint32_t d);
};
