#pragma once

#include "peCommon.h"
#include "outputCapture.h"
#include <vector>
#include <string>
#include <chrono>

/**
 * Digital Signature Analysis for PE files
 * Parses Authenticode signatures and certificate chains
 */
class PEDigitalSignatureAnalyzer {
public:
    struct CertificateInfo {
        std::string issuer;
        std::string subject;
        std::string serialNumber;
        std::string thumbprint;
        std::string algorithm;
        std::chrono::system_clock::time_point notBefore;
        std::chrono::system_clock::time_point notAfter;
        bool isValid;
        bool isExpired;
        bool isSelfSigned;
    };
    
    struct SignatureInfo {
        bool isSigned;
        bool isValid;
        bool isCounterSigned;
        std::string digestAlgorithm;
        std::string signatureAlgorithm;
        std::string programName;
        std::string publisherLink;
        std::string moreInfoLink;
        std::chrono::system_clock::time_point signingTime;
        std::chrono::system_clock::time_point counterSigningTime;
        std::vector<CertificateInfo> certificateChain;
        std::string errorMessage;
    };
    
    struct SecurityCatalogInfo {
        bool isInCatalog;
        std::string catalogFile;
        std::string catalogHash;
    };

    explicit PEDigitalSignatureAnalyzer(PPE_FILE_INFO pFileInfo);
    ~PEDigitalSignatureAnalyzer() = default;
    
    // Main analysis methods
    SignatureInfo analyzeSignature();
    SecurityCatalogInfo checkSecurityCatalog();
    
    // Certificate chain analysis
    std::vector<CertificateInfo> parseCertificateChain(const BYTE* certData, size_t certSize);
    bool verifyCertificateChain(const std::vector<CertificateInfo>& chain);
    
    // Signature verification
    bool verifyAuthenticodeSignature();
    bool verifyFileHash();
    
    // Print analysis results
    void printSignatureInfo();
    void printCertificateChain();
    void printSecurityCatalog();
    
    // JSON output
    std::string toJson() const;
    
    // Utility methods
    static std::string formatTime(const std::chrono::system_clock::time_point& timePoint);
    static std::string bytesToHex(const BYTE* data, size_t size);

private:
    PPE_FILE_INFO pFileInfo_;
    SignatureInfo signatureInfo_;
    SecurityCatalogInfo catalogInfo_;
    
    // Helper methods
    bool extractSignatureData(BYTE** signatureData, DWORD* signatureSize);
    bool parseWinCertificate(const BYTE* certData, size_t certSize);
    bool parsePKCS7Signature(const BYTE* pkcs7Data, size_t pkcs7Size);
    std::string extractStringFromCertificate(const BYTE* certData, const char* oid);
    bool isSignatureExpired(const std::chrono::system_clock::time_point& signingTime);
    bool verifySignatureIntegrity(const BYTE* signatureData, size_t signatureSize);
    
    // Certificate parsing helpers
    bool parseCertificateFields(const BYTE* certData, size_t certSize, CertificateInfo& certInfo);
    std::string getAlgorithmName(const std::string& oid);
    std::chrono::system_clock::time_point parseASN1Time(const BYTE* timeData, size_t timeSize);
    
    // Hash calculation
    std::string calculateFileHash(const std::string& algorithm = "SHA256");
    std::string calculateSectionHash(DWORD sectionRVA, DWORD sectionSize, const std::string& algorithm = "SHA256");
};
