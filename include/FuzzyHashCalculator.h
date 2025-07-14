#ifndef FUZZY_HASH_CALCULATOR_H
#define FUZZY_HASH_CALCULATOR_H

#include <string>
#include <vector>
#include <cstdint>

class FuzzyHashCalculator {
public:
    FuzzyHashCalculator();
    ~FuzzyHashCalculator();
    
    // Real ssdeep implementation using libfuzzy
    std::string calculateSSDeep(const uint8_t* data, size_t size);
    std::string calculateSSDeep(const std::string& filePath);
    
    // Custom implementations for specialized hashes
    std::string calculateTLSH(const uint8_t* data, size_t size);
    std::string calculateVHash(const uint8_t* data, size_t size);
    
    struct FuzzyHashes {
        std::string ssdeep;
        std::string tlsh;
        std::string vhash;
        bool success;
    };
    
    FuzzyHashes calculateAllHashes(const std::string& filePath);
    
    // Real ssdeep comparison using libfuzzy
    int compareSSDeep(const std::string& hash1, const std::string& hash2);
    int compareTLSH(const std::string& hash1, const std::string& hash2);
private:
    // Custom TLSH implementation structures (keeping existing)
    struct TLSHState {
        uint32_t checksum;
        uint32_t sliding_window;
        std::vector<uint32_t> bucket_array;
        uint32_t data_len;
    };
    void initTLSHState(TLSHState& state);
    void updateTLSHHash(TLSHState& state, const uint8_t* data, size_t len);
    std::string finalizeTLSHHash(TLSHState& state);
    
    // Custom VHash implementation structures (keeping existing)
    struct VHashState {
        std::vector<uint8_t> features;
        uint32_t section_count;
        uint32_t import_count;
        uint32_t export_count;
    };
    void extractVHashFeatures(VHashState& state, const uint8_t* data, size_t size);
    std::string finalizeVHash(VHashState& state);
    
    // Utility functions
    uint32_t rollingHash(const uint8_t* data, size_t len);
    uint8_t calculatePearsonHash(const uint8_t* data, size_t len);
    std::string base64Encode(const std::vector<uint8_t>& data);
};
#endif 
