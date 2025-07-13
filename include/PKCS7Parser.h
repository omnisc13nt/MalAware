#pragma once
#include <stdint.h>
#include <vector>
#include <string>
namespace PKCS7 {
    struct ContentInfo {
        std::vector<uint8_t> contentType;
        std::vector<uint8_t> content;
    };
    struct SignedData {
        int version;
        std::vector<uint8_t> digestAlgorithms;
        ContentInfo contentInfo;
        std::vector<uint8_t> certificates;
        std::vector<uint8_t> signerInfos;
    };
    struct Certificate {
        std::vector<uint8_t> tbsCertificate;
        std::vector<uint8_t> signatureAlgorithm;
        std::vector<uint8_t> signatureValue;
        std::string subject;
        std::string issuer;
        std::string serialNumber;
        uint64_t notBefore;
        uint64_t notAfter;
        bool isValid;
    };
    struct SignerInfo {
        int version;
        std::vector<uint8_t> issuerAndSerialNumber;
        std::vector<uint8_t> digestAlgorithm;
        std::vector<uint8_t> authenticatedAttributes;
        std::vector<uint8_t> digestEncryptionAlgorithm;
        std::vector<uint8_t> encryptedDigest;
        std::vector<uint8_t> unauthenticatedAttributes;
    };
}
class PKCS7Parser {
public:
    static bool parseContentInfo(const uint8_t* data, size_t size, PKCS7::ContentInfo& contentInfo);
    static bool parseSignedData(const uint8_t* data, size_t size, PKCS7::SignedData& signedData);
    static bool parseCertificate(const uint8_t* data, size_t size, PKCS7::Certificate& cert);
    static bool parseSignerInfo(const uint8_t* data, size_t size, PKCS7::SignerInfo& signerInfo);
    static bool parseASN1Length(const uint8_t* data, size_t& pos, size_t dataSize, size_t& length);
    static bool parseASN1Tag(const uint8_t* data, size_t& pos, size_t dataSize, uint8_t expectedTag);
    static bool parseASN1Sequence(const uint8_t* data, size_t& pos, size_t dataSize, std::vector<uint8_t>& content);
    static bool parseASN1OID(const uint8_t* data, size_t& pos, size_t dataSize, std::vector<uint8_t>& oid);
    static bool parseASN1Integer(const uint8_t* data, size_t& pos, size_t dataSize, std::vector<uint8_t>& integer);
    static bool parseASN1UTCTime(const uint8_t* data, size_t& pos, size_t dataSize, uint64_t& timestamp);
    static bool parseASN1GeneralizedTime(const uint8_t* data, size_t& pos, size_t dataSize, uint64_t& timestamp);
    static bool validateCertificateChain(const std::vector<PKCS7::Certificate>& certs);
    static bool verifyCertificateSignature(const PKCS7::Certificate& cert, const PKCS7::Certificate& issuer);
    static bool isCertificateExpired(const PKCS7::Certificate& cert);
    static std::string oidToString(const std::vector<uint8_t>& oid);
    static bool isSignatureAlgorithmOID(const std::vector<uint8_t>& oid);
    static bool isDigestAlgorithmOID(const std::vector<uint8_t>& oid);
};
