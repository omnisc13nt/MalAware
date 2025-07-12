#pragma once

#include "peCommon.h"
#include <string>
#include <vector>
#include <map>

/**
 * Hash Calculator for PE files
 * Implements various hash algorithms for malware analysis
 */
class PEHashCalculator {
public:
    struct HashResult {
        std::string md5;
        std::string sha1;
        std::string sha256;
        std::string imphash;      // Import hash
        std::string authentihash; // Authenticode hash
        std::string ssdeep;       // Fuzzy hash
        std::string tlsh;         // Trend Micro Locality Sensitive Hash
        std::string vhash;        // VirusTotal hash
    };
    
    struct SectionHashes {
        std::string sectionName;
        std::string md5;
        std::string sha1;
        std::string sha256;
        double entropy;
        double chi2;
        DWORD virtualAddress;
        DWORD virtualSize;
        DWORD rawSize;
    };
    
    struct FileInfo {
        std::string fileType;
        std::string magic;
        std::string architecture;
        DWORD fileSize;
        DWORD compilationTimestamp;
        DWORD entryPoint;
        int numberOfSections;
        bool isSigned;
        std::string detectedPacker;
    };

    explicit PEHashCalculator(PPE_FILE_INFO pFileInfo);
    ~PEHashCalculator() = default;
    
    // Hash calculation methods
    HashResult calculateAllHashes();
    std::string calculateMD5();
    std::string calculateSHA1();
    std::string calculateSHA256();
    std::string calculateImphash();
    std::string calculateAuthentihash();
    std::string calculateSSDeep();
    std::string calculateTLSH();
    std::string calculateVHash();
    
    // Section-specific hashes
    std::vector<SectionHashes> calculateSectionHashes();
    
    // File information
    FileInfo extractFileInfo();
    
    // Overlay analysis
    struct OverlayInfo {
        bool hasOverlay;
        DWORD offset;
        DWORD size;
        std::string md5;
        std::string sha256;
        double entropy;
        double chi2;
        std::string fileType;
    };
    OverlayInfo analyzeOverlay();
    
    // Print methods
    void printFileHashes();
    void printSectionHashes();
    void printFileInfo();
    void printOverlayInfo();
    
    // JSON output
    std::string toJson() const;

private:
    PPE_FILE_INFO pFileInfo_;
    HashResult hashResult_;
    std::vector<SectionHashes> sectionHashes_;
    FileInfo fileInfo_;
    OverlayInfo overlayInfo_;
    
    // Hash calculation helpers
    std::string calculateHash(const BYTE* data, size_t size, const std::string& algorithm);
    std::string calculateFileHash(const std::string& algorithm);
    std::string calculateSectionHash(const BYTE* data, size_t size, const std::string& algorithm);
    
    // Simple hash implementations (for educational purposes)
    std::string calculateMD5Simple(const BYTE* data, size_t size);
    std::string calculateSHA1Simple(const BYTE* data, size_t size);
    std::string calculateSHA256Simple(const BYTE* data, size_t size);
    
    // Import hash calculation
    std::string calculateImportHash();
    std::vector<std::string> extractImportedFunctions();
    
    // Entropy and Chi-square calculation
    double calculateEntropy(const BYTE* data, size_t size);
    double calculateChi2(const BYTE* data, size_t size);
    
    // File type detection
    std::string detectFileType();
    std::string getMagicSignature();
    
    // Utility methods
    std::string bytesToHex(const BYTE* data, size_t size);
    std::string toLowerCase(const std::string& str);
    DWORD getFileSize();
    DWORD getLastSectionEnd();
};
