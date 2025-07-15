#include "../include/CryptoUtils.h"
const uint32_t CryptoUtils::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
uint32_t CryptoUtils::rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}
uint32_t CryptoUtils::ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}
uint32_t CryptoUtils::maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
uint32_t CryptoUtils::sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}
uint32_t CryptoUtils::sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}
uint32_t CryptoUtils::Sig0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
uint32_t CryptoUtils::Sig1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
std::string CryptoUtils::sha256(const uint8_t* data, size_t length) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint64_t bitLen = length * 8;
    size_t paddedLen = length + 1;
    while ((paddedLen % 64) != 56) {
        paddedLen++;
    }
    paddedLen += 8;
    uint8_t* paddedData = new uint8_t[paddedLen]();
    memcpy(paddedData, data, length);
    paddedData[length] = 0x80;
    for (int i = 0; i < 8; i++) {
        paddedData[paddedLen - 1 - i] = (bitLen >> (i * 8)) & 0xFF;
    }
    for (size_t chunk = 0; chunk < paddedLen; chunk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = (paddedData[chunk + i * 4] << 24) |
                   (paddedData[chunk + i * 4 + 1] << 16) |
                   (paddedData[chunk + i * 4 + 2] << 8) |
                   (paddedData[chunk + i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], h_temp = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t T1 = h_temp + Sig1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t T2 = Sig0(a) + maj(a, b, c);
            h_temp = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h_temp;
    }
    delete[] paddedData;
    std::stringstream ss;
    for (int i = 0; i < 8; i++) {
        ss << std::hex << std::setw(8) << std::setfill('0') << h[i];
    }
    return ss.str();
}
const uint32_t CryptoUtils::MD5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
uint32_t CryptoUtils::md5_rotleft(uint32_t value, int amount) {
    return (value << amount) | (value >> (32 - amount));
}
uint32_t CryptoUtils::md5_f(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}
uint32_t CryptoUtils::md5_g(uint32_t x, uint32_t y, uint32_t z) {
    return (x & z) | (y & ~z);
}
uint32_t CryptoUtils::md5_h(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}
uint32_t CryptoUtils::md5_i(uint32_t x, uint32_t y, uint32_t z) {
    return y ^ (x | ~z);
}
std::string CryptoUtils::md5(const uint8_t* data, size_t length) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint64_t bitLen = length * 8;
    size_t paddedLen = length + 1;
    while ((paddedLen % 64) != 56) {
        paddedLen++;
    }
    paddedLen += 8;
    uint8_t* paddedData = new uint8_t[paddedLen]();
    memcpy(paddedData, data, length);
    paddedData[length] = 0x80;
    for (int i = 0; i < 8; i++) {
        paddedData[paddedLen - 8 + i] = (bitLen >> (i * 8)) & 0xFF;
    }
    for (size_t chunk = 0; chunk < paddedLen; chunk += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++) {
            w[i] = paddedData[chunk + i * 4] |
                   (paddedData[chunk + i * 4 + 1] << 8) |
                   (paddedData[chunk + i * 4 + 2] << 16) |
                   (paddedData[chunk + i * 4 + 3] << 24);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3;
        for (int i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16) {
                f = md5_f(b, c, d);
                g = i;
            } else if (i < 32) {
                f = md5_g(b, c, d);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = md5_h(b, c, d);
                g = (3 * i + 5) % 16;
            } else {
                f = md5_i(b, c, d);
                g = (7 * i) % 16;
            }
            f = f + a + MD5_K[i] + w[g];
            a = d;
            d = c;
            c = b;
            b = b + md5_rotleft(f, (i < 16) ? (i % 4 == 0 ? 7 : i % 4 == 1 ? 12 : i % 4 == 2 ? 17 : 22) :
                                     (i < 32) ? (i % 4 == 0 ? 5 : i % 4 == 1 ? 9 : i % 4 == 2 ? 14 : 20) :
                                     (i < 48) ? (i % 4 == 0 ? 4 : i % 4 == 1 ? 11 : i % 4 == 2 ? 16 : 23) :
                                               (i % 4 == 0 ? 6 : i % 4 == 1 ? 10 : i % 4 == 2 ? 15 : 21));
        }
        h0 += a; h1 += b; h2 += c; h3 += d;
    }
    delete[] paddedData;
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') <<
          ((h0 & 0xFF) << 24 | ((h0 >> 8) & 0xFF) << 16 | ((h0 >> 16) & 0xFF) << 8 | (h0 >> 24));
    ss << std::hex << std::setw(8) << std::setfill('0') <<
          ((h1 & 0xFF) << 24 | ((h1 >> 8) & 0xFF) << 16 | ((h1 >> 16) & 0xFF) << 8 | (h1 >> 24));
    ss << std::hex << std::setw(8) << std::setfill('0') <<
          ((h2 & 0xFF) << 24 | ((h2 >> 8) & 0xFF) << 16 | ((h2 >> 16) & 0xFF) << 8 | (h2 >> 24));
    ss << std::hex << std::setw(8) << std::setfill('0') <<
          ((h3 & 0xFF) << 24 | ((h3 >> 8) & 0xFF) << 16 | ((h3 >> 16) & 0xFF) << 8 | (h3 >> 24));
    return ss.str();
}
uint32_t CryptoUtils::sha1_rotleft(uint32_t value, int amount) {
    return (value << amount) | (value >> (32 - amount));
}
uint32_t CryptoUtils::sha1_f(int t, uint32_t b, uint32_t c, uint32_t d) {
    if (t < 20) return (b & c) | (~b & d);
    if (t < 40) return b ^ c ^ d;
    if (t < 60) return (b & c) | (b & d) | (c & d);
    return b ^ c ^ d;
}
std::string CryptoUtils::sha1(const uint8_t* data, size_t length) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    uint64_t bitLen = length * 8;
    size_t paddedLen = length + 1;
    while ((paddedLen % 64) != 56) {
        paddedLen++;
    }
    paddedLen += 8;
    uint8_t* paddedData = new uint8_t[paddedLen]();
    memcpy(paddedData, data, length);
    paddedData[length] = 0x80;
    for (int i = 0; i < 8; i++) {
        paddedData[paddedLen - 1 - i] = (bitLen >> (i * 8)) & 0xFF;
    }
    for (size_t chunk = 0; chunk < paddedLen; chunk += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = (paddedData[chunk + i * 4] << 24) |
                   (paddedData[chunk + i * 4 + 1] << 16) |
                   (paddedData[chunk + i * 4 + 2] << 8) |
                   (paddedData[chunk + i * 4 + 3]);
        }
        for (int i = 16; i < 80; i++) {
            w[i] = sha1_rotleft(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; i++) {
            uint32_t k;
            if (i < 20) k = 0x5A827999;
            else if (i < 40) k = 0x6ED9EBA1;
            else if (i < 60) k = 0x8F1BBCDC;
            else k = 0xCA62C1D6;
            uint32_t temp = sha1_rotleft(a, 5) + sha1_f(i, b, c, d) + e + k + w[i];
            e = d;
            d = c;
            c = sha1_rotleft(b, 30);
            b = a;
            a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    delete[] paddedData;
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << h0;
    ss << std::hex << std::setw(8) << std::setfill('0') << h1;
    ss << std::hex << std::setw(8) << std::setfill('0') << h2;
    ss << std::hex << std::setw(8) << std::setfill('0') << h3;
    ss << std::hex << std::setw(8) << std::setfill('0') << h4;
    return ss.str();
}
