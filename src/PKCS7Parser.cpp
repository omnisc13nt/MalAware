#include "../include/PKCS7Parser.h"
#include "../include/CryptoUtils.h"
#include <cstring>
#include <ctime>
#include <sstream>
#include <iomanip>
const uint8_t ASN1_SEQUENCE = 0x30;
const uint8_t ASN1_SET = 0x31;
const uint8_t ASN1_INTEGER = 0x02;
const uint8_t ASN1_OCTET_STRING = 0x04;
const uint8_t ASN1_OID = 0x06;
const uint8_t ASN1_UTC_TIME = 0x17;
const uint8_t ASN1_GENERALIZED_TIME = 0x18;
const uint8_t ASN1_CONTEXT_SPECIFIC = 0xA0;
const std::vector<uint8_t> OID_PKCS7_SIGNED_DATA = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
const std::vector<uint8_t> OID_SHA256_WITH_RSA = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
const std::vector<uint8_t> OID_SHA1_WITH_RSA = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05};
const std::vector<uint8_t> OID_MD5_WITH_RSA = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04};
bool PKCS7Parser::parseASN1Length(const uint8_t* data, size_t& pos, size_t dataSize, size_t& length) {
    if (pos >= dataSize) return false;
    uint8_t firstByte = data[pos++];
    if ((firstByte & 0x80) == 0) {
        length = firstByte;
        return true;
    }
    uint8_t numOctets = firstByte & 0x7F;
    if (numOctets == 0 || numOctets > 4 || pos + numOctets > dataSize) {
        return false;
    }
    length = 0;
    for (int i = 0; i < numOctets; i++) {
        length = (length << 8) | data[pos++];
    }
    return pos + length <= dataSize;
}
bool PKCS7Parser::parseASN1Tag(const uint8_t* data, size_t& pos, size_t dataSize, uint8_t expectedTag) {
    if (pos >= dataSize) return false;
    if (data[pos] != expectedTag) return false;
    pos++;
    return true;
}
bool PKCS7Parser::parseASN1Sequence(const uint8_t* data, size_t& pos, size_t dataSize, std::vector<uint8_t>& content) {
    if (!parseASN1Tag(data, pos, dataSize, ASN1_SEQUENCE)) return false;
    size_t length;
    if (!parseASN1Length(data, pos, dataSize, length)) return false;
    if (pos + length > dataSize) return false;
    content.assign(data + pos, data + pos + length);
    pos += length;
    return true;
}
bool PKCS7Parser::parseASN1OID(const uint8_t* data, size_t& pos, size_t dataSize, std::vector<uint8_t>& oid) {
    if (!parseASN1Tag(data, pos, dataSize, ASN1_OID)) return false;
    size_t length;
    if (!parseASN1Length(data, pos, dataSize, length)) return false;
    if (pos + length > dataSize) return false;
    oid.assign(data + pos, data + pos + length);
    pos += length;
    return true;
}
bool PKCS7Parser::parseASN1Integer(const uint8_t* data, size_t& pos, size_t dataSize, std::vector<uint8_t>& integer) {
    if (!parseASN1Tag(data, pos, dataSize, ASN1_INTEGER)) return false;
    size_t length;
    if (!parseASN1Length(data, pos, dataSize, length)) return false;
    if (pos + length > dataSize) return false;
    integer.assign(data + pos, data + pos + length);
    pos += length;
    return true;
}
bool PKCS7Parser::parseASN1UTCTime(const uint8_t* data, size_t& pos, size_t dataSize, uint64_t& timestamp) {
    if (!parseASN1Tag(data, pos, dataSize, ASN1_UTC_TIME)) return false;
    size_t length;
    if (!parseASN1Length(data, pos, dataSize, length)) return false;
    if (pos + length > dataSize || length < 10) return false;
    std::string timeStr(reinterpret_cast<const char*>(data + pos), length);
    pos += length;
    struct tm timeinfo = {};
    if (timeStr.length() >= 10) {
        timeinfo.tm_year = std::stoi(timeStr.substr(0, 2)) + 100;
        timeinfo.tm_mon = std::stoi(timeStr.substr(2, 2)) - 1;
        timeinfo.tm_mday = std::stoi(timeStr.substr(4, 2));
        timeinfo.tm_hour = std::stoi(timeStr.substr(6, 2));
        timeinfo.tm_min = std::stoi(timeStr.substr(8, 2));
        if (timeStr.length() >= 12) {
            timeinfo.tm_sec = std::stoi(timeStr.substr(10, 2));
        }
    }
    timestamp = static_cast<uint64_t>(mktime(&timeinfo));
    return true;
}
bool PKCS7Parser::parseASN1GeneralizedTime(const uint8_t* data, size_t& pos, size_t dataSize, uint64_t& timestamp) {
    if (!parseASN1Tag(data, pos, dataSize, ASN1_GENERALIZED_TIME)) return false;
    size_t length;
    if (!parseASN1Length(data, pos, dataSize, length)) return false;
    if (pos + length > dataSize || length < 12) return false;
    std::string timeStr(reinterpret_cast<const char*>(data + pos), length);
    pos += length;
    struct tm timeinfo = {};
    if (timeStr.length() >= 12) {
        timeinfo.tm_year = std::stoi(timeStr.substr(0, 4)) - 1900;
        timeinfo.tm_mon = std::stoi(timeStr.substr(4, 2)) - 1;
        timeinfo.tm_mday = std::stoi(timeStr.substr(6, 2));
        timeinfo.tm_hour = std::stoi(timeStr.substr(8, 2));
        timeinfo.tm_min = std::stoi(timeStr.substr(10, 2));
        if (timeStr.length() >= 14) {
            timeinfo.tm_sec = std::stoi(timeStr.substr(12, 2));
        }
    }
    timestamp = static_cast<uint64_t>(mktime(&timeinfo));
    return true;
}
bool PKCS7Parser::parseContentInfo(const uint8_t* data, size_t size, PKCS7::ContentInfo& contentInfo) {
    size_t pos = 0;
    if (!parseASN1Tag(data, pos, size, ASN1_SEQUENCE)) return false;
    size_t seqLength;
    if (!parseASN1Length(data, pos, size, seqLength)) return false;
    if (!parseASN1OID(data, pos, size, contentInfo.contentType)) return false;
    if (contentInfo.contentType != OID_PKCS7_SIGNED_DATA) {
        return false;
    }
    if (pos < size && data[pos] == ASN1_CONTEXT_SPECIFIC) {
        pos++;
        size_t contentLength;
        if (!parseASN1Length(data, pos, size, contentLength)) return false;
        contentInfo.content.assign(data + pos, data + pos + contentLength);
        pos += contentLength;
    }
    return true;
}
bool PKCS7Parser::parseSignedData(const uint8_t* data, size_t size, PKCS7::SignedData& signedData) {
    size_t pos = 0;
    if (!parseASN1Tag(data, pos, size, ASN1_SEQUENCE)) return false;
    size_t seqLength;
    if (!parseASN1Length(data, pos, size, seqLength)) return false;
    std::vector<uint8_t> versionBytes;
    if (!parseASN1Integer(data, pos, size, versionBytes)) return false;
    signedData.version = versionBytes.empty() ? 0 : versionBytes[0];
    if (!parseASN1Tag(data, pos, size, ASN1_SET)) return false;
    size_t digestAlgLength;
    if (!parseASN1Length(data, pos, size, digestAlgLength)) return false;
    signedData.digestAlgorithms.assign(data + pos, data + pos + digestAlgLength);
    pos += digestAlgLength;
    std::vector<uint8_t> contentInfoBytes;
    if (!parseASN1Sequence(data, pos, size, contentInfoBytes)) return false;
    parseContentInfo(contentInfoBytes.data(), contentInfoBytes.size(), signedData.contentInfo);
    if (pos < size && (data[pos] & 0xDF) == 0xA0) {
        pos++;
        size_t certLength;
        if (!parseASN1Length(data, pos, size, certLength)) return false;
        signedData.certificates.assign(data + pos, data + pos + certLength);
        pos += certLength;
    }
    if (pos < size && (data[pos] & 0xDF) == 0xA1) {
        pos++;
        size_t crlLength;
        if (!parseASN1Length(data, pos, size, crlLength)) return false;
        pos += crlLength;
    }
    if (!parseASN1Tag(data, pos, size, ASN1_SET)) return false;
    size_t signerInfoLength;
    if (!parseASN1Length(data, pos, size, signerInfoLength)) return false;
    signedData.signerInfos.assign(data + pos, data + pos + signerInfoLength);
    return true;
}
bool PKCS7Parser::parseCertificate(const uint8_t* data, size_t size, PKCS7::Certificate& cert) {
    size_t pos = 0;
    if (!parseASN1Tag(data, pos, size, ASN1_SEQUENCE)) return false;
    size_t certLength;
    if (!parseASN1Length(data, pos, size, certLength)) return false;
    size_t tbsStart = pos;
    if (!parseASN1Tag(data, pos, size, ASN1_SEQUENCE)) return false;
    size_t tbsLength;
    if (!parseASN1Length(data, pos, size, tbsLength)) return false;
    cert.tbsCertificate.assign(data + tbsStart, data + pos + tbsLength);
    size_t tbsPos = pos;
    if (tbsPos < size && (data[tbsPos] & 0xDF) == 0xA0) {
        tbsPos++;
        size_t versionLength;
        if (!parseASN1Length(data, tbsPos, size, versionLength)) return false;
        tbsPos += versionLength;
    }
    std::vector<uint8_t> serialBytes;
    if (!parseASN1Integer(data, tbsPos, size, serialBytes)) return false;
    std::stringstream ss;
    for (uint8_t b : serialBytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    cert.serialNumber = ss.str();
    std::vector<uint8_t> sigAlg;
    if (!parseASN1Sequence(data, tbsPos, size, sigAlg)) return false;
    std::vector<uint8_t> issuerBytes;
    if (!parseASN1Sequence(data, tbsPos, size, issuerBytes)) return false;
    cert.issuer = "Issuer DN";
    if (!parseASN1Tag(data, tbsPos, size, ASN1_SEQUENCE)) return false;
    size_t validityLength;
    if (!parseASN1Length(data, tbsPos, size, validityLength)) return false;
    if (data[tbsPos] == ASN1_UTC_TIME) {
        parseASN1UTCTime(data, tbsPos, size, cert.notBefore);
    } else if (data[tbsPos] == ASN1_GENERALIZED_TIME) {
        parseASN1GeneralizedTime(data, tbsPos, size, cert.notBefore);
    }
    if (data[tbsPos] == ASN1_UTC_TIME) {
        parseASN1UTCTime(data, tbsPos, size, cert.notAfter);
    } else if (data[tbsPos] == ASN1_GENERALIZED_TIME) {
        parseASN1GeneralizedTime(data, tbsPos, size, cert.notAfter);
    }
    std::vector<uint8_t> subjectBytes;
    if (!parseASN1Sequence(data, tbsPos, size, subjectBytes)) return false;
    cert.subject = "Subject DN";
    pos += tbsLength;
    if (!parseASN1Sequence(data, pos, size, cert.signatureAlgorithm)) return false;
    if (!parseASN1Tag(data, pos, size, 0x03)) return false;
    size_t sigValueLength;
    if (!parseASN1Length(data, pos, size, sigValueLength)) return false;
    cert.signatureValue.assign(data + pos, data + pos + sigValueLength);
    uint64_t currentTime = static_cast<uint64_t>(time(nullptr));
    cert.isValid = (currentTime >= cert.notBefore && currentTime <= cert.notAfter);
    return true;
}
bool PKCS7Parser::parseSignerInfo(const uint8_t* data, size_t size, PKCS7::SignerInfo& signerInfo) {
    size_t pos = 0;
    if (!parseASN1Tag(data, pos, size, ASN1_SEQUENCE)) return false;
    size_t seqLength;
    if (!parseASN1Length(data, pos, size, seqLength)) return false;
    std::vector<uint8_t> versionBytes;
    if (!parseASN1Integer(data, pos, size, versionBytes)) return false;
    signerInfo.version = versionBytes.empty() ? 0 : versionBytes[0];
    if (!parseASN1Sequence(data, pos, size, signerInfo.issuerAndSerialNumber)) return false;
    if (!parseASN1Sequence(data, pos, size, signerInfo.digestAlgorithm)) return false;
    if (pos < size && (data[pos] & 0xDF) == 0xA0) {
        pos++;
        size_t attrLength;
        if (!parseASN1Length(data, pos, size, attrLength)) return false;
        signerInfo.authenticatedAttributes.assign(data + pos, data + pos + attrLength);
        pos += attrLength;
    }
    if (!parseASN1Sequence(data, pos, size, signerInfo.digestEncryptionAlgorithm)) return false;
    if (!parseASN1Tag(data, pos, size, ASN1_OCTET_STRING)) return false;
    size_t encDigestLength;
    if (!parseASN1Length(data, pos, size, encDigestLength)) return false;
    signerInfo.encryptedDigest.assign(data + pos, data + pos + encDigestLength);
    pos += encDigestLength;
    if (pos < size && (data[pos] & 0xDF) == 0xA1) {
        pos++;
        size_t unattrLength;
        if (!parseASN1Length(data, pos, size, unattrLength)) return false;
        signerInfo.unauthenticatedAttributes.assign(data + pos, data + pos + unattrLength);
    }
    return true;
}
bool PKCS7Parser::validateCertificateChain(const std::vector<PKCS7::Certificate>& certs) {
    if (certs.empty()) return false;
    for (const auto& cert : certs) {
        if (!cert.isValid) {
            return false;
        }
    }
    return true;
}
bool PKCS7Parser::verifyCertificateSignature(const PKCS7::Certificate& cert, const PKCS7::Certificate& issuer) {


    if (!cert.isValid || !issuer.isValid) {
        return false;
    }


    if (cert.issuer.empty() || cert.subject.empty()) {
        return false;
    }


    if (isCertificateExpired(cert)) {
        return false;
    }


    if (cert.signatureValue.empty() || cert.signatureAlgorithm.empty()) {
        return false;
    }


    if (!isSignatureAlgorithmOID(cert.signatureAlgorithm)) {
        return false;
    }


    bool hasValidStructure = (!cert.serialNumber.empty() &&
                             !cert.tbsCertificate.empty() &&
                             cert.signatureValue.size() >= 128);

    return hasValidStructure;
}
bool PKCS7Parser::isCertificateExpired(const PKCS7::Certificate& cert) {
    uint64_t currentTime = static_cast<uint64_t>(time(nullptr));
    return currentTime < cert.notBefore || currentTime > cert.notAfter;
}
std::string PKCS7Parser::oidToString(const std::vector<uint8_t>& oid) {
    if (oid.empty()) return "";
    std::stringstream ss;
    if (!oid.empty()) {
        uint8_t firstByte = oid[0];
        ss << (firstByte / 40) << "." << (firstByte % 40);
    }
    for (size_t i = 1; i < oid.size(); ) {
        uint32_t component = 0;
        do {
            component = (component << 7) | (oid[i] & 0x7F);
            i++;
        } while (i < oid.size() && (oid[i-1] & 0x80));
        ss << "." << component;
    }
    return ss.str();
}
bool PKCS7Parser::isSignatureAlgorithmOID(const std::vector<uint8_t>& oid) {
    return oid == OID_SHA256_WITH_RSA || oid == OID_SHA1_WITH_RSA || oid == OID_MD5_WITH_RSA;
}
bool PKCS7Parser::isDigestAlgorithmOID(const std::vector<uint8_t>& oid) {
    const std::vector<uint8_t> OID_MD5 = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05};
    const std::vector<uint8_t> OID_SHA1 = {0x2B, 0x0E, 0x03, 0x02, 0x1A};
    const std::vector<uint8_t> OID_SHA256 = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
    return oid == OID_MD5 || oid == OID_SHA1 || oid == OID_SHA256;
}
