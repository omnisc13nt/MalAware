#include "../include/PEDigitalSignatureAnalyzer.h"
#include "../include/PKCS7Parser.h"
#include "../include/CryptoUtils.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <ctime>
PEDigitalSignatureAnalyzer::PEDigitalSignatureAnalyzer(PPE_FILE_INFO pFileInfo) : pFileInfo_(pFileInfo) {
    signatureInfo_ = {};
    catalogInfo_ = {};
}
PEDigitalSignatureAnalyzer::SignatureInfo PEDigitalSignatureAnalyzer::analyzeSignature() {
    signatureInfo_ = {};
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        signatureInfo_.errorMessage = "Invalid PE file structure";
        return signatureInfo_;
    }
    PIMAGE_DATA_DIRECTORY securityDir = nullptr;
    if (pFileInfo_->bIs64Bit) {
        auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo_->pNtHeader;
        if (pNtHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            securityDir = &pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        }
    } else {
        auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo_->pNtHeader;
        if (pNtHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            securityDir = &pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        }
    }
    if (!securityDir || securityDir->Size == 0) {
        signatureInfo_.isSigned = false;
        signatureInfo_.errorMessage = "No digital signature found";
        return signatureInfo_;
    }
    BYTE* signatureData = nullptr;
    DWORD signatureSize = 0;
    if (!extractSignatureData(&signatureData, &signatureSize)) {
        signatureInfo_.errorMessage = "Failed to extract signature data from PE security directory. The file may be corrupted or the security directory may be invalid.";
        return signatureInfo_;
    }
    signatureInfo_.isSigned = true;
    if (!parseWinCertificate(signatureData, signatureSize)) {

        return signatureInfo_;
    }
    signatureInfo_.isValid = verifySignatureIntegrity(signatureData, signatureSize);
    return signatureInfo_;
}
bool PEDigitalSignatureAnalyzer::extractSignatureData(BYTE** signatureData, DWORD* signatureSize) {
    if (!pFileInfo_ || !signatureData || !signatureSize) {
        return false;
    }
    PIMAGE_DATA_DIRECTORY securityDir = nullptr;
    if (pFileInfo_->bIs64Bit) {
        auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo_->pNtHeader;
        securityDir = &pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else {
        auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo_->pNtHeader;
        securityDir = &pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
    if (!securityDir || securityDir->Size == 0) {
        return false;
    }
    *signatureData = (BYTE*)((DWORD_PTR)pFileInfo_->pDosHeader + securityDir->VirtualAddress);
    *signatureSize = securityDir->Size;
    return true;
}
bool PEDigitalSignatureAnalyzer::parseWinCertificate(const BYTE* certData, size_t certSize) {
    if (!certData || certSize < 8) {
        signatureInfo_.errorMessage = "Failed to parse WIN_CERTIFICATE structure: Certificate data too small (minimum 8 bytes required for WIN_CERTIFICATE header)";
        return false;
    }

    DWORD dwLength = *(DWORD*)certData;
    WORD wRevision = *(WORD*)(certData + 4);
    (void)wRevision;
    WORD wCertificateType = *(WORD*)(certData + 6);

    if (dwLength > certSize) {
        signatureInfo_.errorMessage = "Failed to parse WIN_CERTIFICATE structure: Certificate length field exceeds available data. This may indicate a corrupted or malformed certificate.";
        return false;
    }

    if (dwLength < 8) {
        signatureInfo_.errorMessage = "Failed to parse WIN_CERTIFICATE structure: Invalid certificate length (too small). Minimum size is 8 bytes for header.";
        return false;
    }

    if (wCertificateType == 0x0002) {
        const BYTE* pkcs7Data = certData + 8;
        size_t pkcs7Size = dwLength - 8;

        if (pkcs7Size == 0) {
            signatureInfo_.errorMessage = "Failed to parse WIN_CERTIFICATE structure: Empty PKCS#7 data in certificate. The certificate contains no signature data.";
            return false;
        }

        return parsePKCS7Signature(pkcs7Data, pkcs7Size);
    } else {
        signatureInfo_.errorMessage = "Failed to parse WIN_CERTIFICATE structure: Unsupported certificate type. Only PKCS#7 (type 0x0002) certificates are supported.";
        return false;
    }
}
bool PEDigitalSignatureAnalyzer::parsePKCS7Signature(const BYTE* pkcs7Data, size_t pkcs7Size) {
    if (!pkcs7Data || pkcs7Size == 0) {
        return false;
    }
    PKCS7::ContentInfo contentInfo;
    if (!PKCS7Parser::parseContentInfo(pkcs7Data, pkcs7Size, contentInfo)) {
        signatureInfo_.errorMessage = "Failed to parse PKCS#7 ContentInfo";
        return false;
    }
    PKCS7::SignedData signedData;
    if (!PKCS7Parser::parseSignedData(contentInfo.content.data(), contentInfo.content.size(), signedData)) {
        signatureInfo_.errorMessage = "Failed to parse PKCS#7 SignedData";
        return false;
    }
    if (!signedData.certificates.empty()) {
        size_t pos = 0;
        std::vector<PKCS7::Certificate> certificates;
        while (pos < signedData.certificates.size()) {
            PKCS7::Certificate cert;
            size_t remaining = signedData.certificates.size() - pos;
            if (PKCS7Parser::parseCertificate(signedData.certificates.data() + pos, remaining, cert)) {
                certificates.push_back(cert);
                signatureInfo_.subjectName = cert.subject;
                signatureInfo_.issuerName = cert.issuer;
                signatureInfo_.serialNumber = cert.serialNumber;
                signatureInfo_.notBefore = cert.notBefore;
                signatureInfo_.notAfter = cert.notAfter;
                if (PKCS7Parser::isCertificateExpired(cert)) {
                    signatureInfo_.isExpired = true;
                }
                pos += cert.tbsCertificate.size() + cert.signatureAlgorithm.size() + cert.signatureValue.size() + 20;
            } else {
                break;
            }
        }
        if (!certificates.empty()) {
            signatureInfo_.isValid = PKCS7Parser::validateCertificateChain(certificates);
        }
    }
    if (!signedData.signerInfos.empty()) {
        PKCS7::SignerInfo signerInfo;
        if (PKCS7Parser::parseSignerInfo(signedData.signerInfos.data(), signedData.signerInfos.size(), signerInfo)) {
            if (!signerInfo.digestAlgorithm.empty()) {
                size_t oidPos = 0;
                std::vector<uint8_t> digestOID;
                if (PKCS7Parser::parseASN1OID(signerInfo.digestAlgorithm.data(), oidPos, signerInfo.digestAlgorithm.size(), digestOID)) {
                    if (PKCS7Parser::isDigestAlgorithmOID(digestOID)) {
                        std::string oidStr = PKCS7Parser::oidToString(digestOID);
                        if (oidStr.find("2.16.840.1.101.3.4.2.1") != std::string::npos) {
                            signatureInfo_.digestAlgorithm = "SHA256";
                        } else if (oidStr.find("1.3.14.3.2.26") != std::string::npos) {
                            signatureInfo_.digestAlgorithm = "SHA1";
                        } else if (oidStr.find("1.2.840.113549.2.5") != std::string::npos) {
                            signatureInfo_.digestAlgorithm = "MD5";
                        } else {
                            signatureInfo_.digestAlgorithm = "Unknown (" + oidStr + ")";
                        }
                    }
                }
            }
            if (!signerInfo.digestEncryptionAlgorithm.empty()) {
                size_t oidPos = 0;
                std::vector<uint8_t> sigOID;
                if (PKCS7Parser::parseASN1OID(signerInfo.digestEncryptionAlgorithm.data(), oidPos, signerInfo.digestEncryptionAlgorithm.size(), sigOID)) {
                    if (PKCS7Parser::isSignatureAlgorithmOID(sigOID)) {
                        signatureInfo_.signatureAlgorithm = "RSA";
                    }
                }
            }
            if (!signerInfo.unauthenticatedAttributes.empty()) {
                signatureInfo_.isCounterSigned = true;
            }
        }
    }
    return true;
}
bool PEDigitalSignatureAnalyzer::verifySignatureIntegrity(const BYTE* signatureData, size_t signatureSize) {
    if (!signatureData || signatureSize == 0) {
        return false;
    }
    PKCS7::ContentInfo contentInfo;
    if (!PKCS7Parser::parseContentInfo(signatureData, signatureSize, contentInfo)) {
        return false;
    }
    PKCS7::SignedData signedData;
    if (!PKCS7Parser::parseSignedData(contentInfo.content.data(), contentInfo.content.size(), signedData)) {
        return false;
    }
    if (signedData.certificates.empty() || signedData.signerInfos.empty()) {
        return false;
    }
    std::vector<PKCS7::Certificate> certificates;
    size_t pos = 0;
    while (pos < signedData.certificates.size()) {
        PKCS7::Certificate cert;
        size_t remaining = signedData.certificates.size() - pos;
        if (PKCS7Parser::parseCertificate(signedData.certificates.data() + pos, remaining, cert)) {
            certificates.push_back(cert);
            pos += cert.tbsCertificate.size() + 20;
        } else {
            break;
        }
    }
    bool chainValid = PKCS7Parser::validateCertificateChain(certificates);
    return chainValid;
}
std::string PEDigitalSignatureAnalyzer::calculateFileHash(const std::string& algorithm) {
    if (!pFileInfo_ || !pFileInfo_->pDosHeader) {
        return "";
    }
    BYTE* fileData = (BYTE*)pFileInfo_->pDosHeader;
    size_t fileSize = pFileInfo_->dwFileSize;
    std::vector<uint8_t> hashData;
    if (algorithm == "SHA256") {
        return CryptoUtils::sha256(fileData, fileSize);
    } else if (algorithm == "SHA1") {
        return CryptoUtils::sha1(fileData, fileSize);
    } else if (algorithm == "MD5") {
        return CryptoUtils::md5(fileData, fileSize);
    }
    return "";
}
void PEDigitalSignatureAnalyzer::printSignatureInfo() {
    LOG("\n[+] DIGITAL SIGNATURE ANALYSIS\n");
    if (!signatureInfo_.isSigned) {
        LOG("\tFile is not digitally signed\n");
        if (!signatureInfo_.errorMessage.empty()) {
            LOGF("\tError: %s\n", signatureInfo_.errorMessage.c_str());
        }
        return;
    }
    LOG("\tFile is digitally signed\n");
    LOGF("\tSignature Valid: %s\n", signatureInfo_.isValid ? "YES" : "NO");
    if (!signatureInfo_.isValid && !signatureInfo_.errorMessage.empty()) {
        LOGF("\tValidation Error: %s\n", signatureInfo_.errorMessage.c_str());
    }
    LOGF("\tDigest Algorithm: %s\n", signatureInfo_.digestAlgorithm.c_str());
    LOGF("\tSignature Algorithm: %s\n", signatureInfo_.signatureAlgorithm.c_str());
    LOGF("\tCounter Signed: %s\n", signatureInfo_.isCounterSigned ? "YES" : "NO");
    if (!signatureInfo_.programName.empty()) {
        LOGF("\tProgram Name: %s\n", signatureInfo_.programName.c_str());
    }
    if (!signatureInfo_.publisherLink.empty()) {
        LOGF("\tPublisher Link: %s\n", signatureInfo_.publisherLink.c_str());
    }
    if (!signatureInfo_.errorMessage.empty()) {
        LOGF("\tError: %s\n", signatureInfo_.errorMessage.c_str());
    }
}
void PEDigitalSignatureAnalyzer::printCertificateChain() {
    if (signatureInfo_.certificateChain.empty()) {
        LOG("\tNo certificate chain information available\n");
        return;
    }
    LOG("\n[+] CERTIFICATE CHAIN\n");
    for (size_t i = 0; i < signatureInfo_.certificateChain.size(); i++) {
        const auto& cert = signatureInfo_.certificateChain[i];
        LOGF("\tCertificate %zu:\n", i + 1);
        LOGF("\t\tSubject: %s\n", cert.subject.c_str());
        LOGF("\t\tIssuer: %s\n", cert.issuer.c_str());
        LOGF("\t\tSerial Number: %s\n", cert.serialNumber.c_str());
        LOGF("\t\tAlgorithm: %s\n", cert.algorithm.c_str());
        LOGF("\t\tValid: %s\n", cert.isValid ? "YES" : "NO");
        LOGF("\t\tExpired: %s\n", cert.isExpired ? "YES" : "NO");
        LOGF("\t\tSelf-Signed: %s\n", cert.isSelfSigned ? "YES" : "NO");
        if (!cert.thumbprint.empty()) {
            LOGF("\t\tThumbprint: %s\n", cert.thumbprint.c_str());
        }
    }
}
void PEDigitalSignatureAnalyzer::printSecurityCatalog() {
    LOG("\n[+] SECURITY CATALOG\n");
    if (catalogInfo_.isInCatalog) {
        LOG("\tFile is listed in security catalog\n");
        if (!catalogInfo_.catalogFile.empty()) {
            LOGF("\tCatalog File: %s\n", catalogInfo_.catalogFile.c_str());
        }
        if (!catalogInfo_.catalogHash.empty()) {
            LOGF("\tCatalog Hash: %s\n", catalogInfo_.catalogHash.c_str());
        }
    } else {
        LOG("\tFile is not listed in security catalog\n");
    }
}
std::string PEDigitalSignatureAnalyzer::formatTime(const std::chrono::system_clock::time_point& timePoint) {
    auto timeT = std::chrono::system_clock::to_time_t(timePoint);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&timeT), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}
std::string PEDigitalSignatureAnalyzer::bytesToHex(const BYTE* data, size_t size) {
    std::stringstream ss;
    for (size_t i = 0; i < size; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)data[i];
    }
    return ss.str();
}
PEDigitalSignatureAnalyzer::SecurityCatalogInfo PEDigitalSignatureAnalyzer::checkSecurityCatalog() {
    catalogInfo_ = {};
    catalogInfo_.isInCatalog = false;
    catalogInfo_.catalogFile = "";
    catalogInfo_.catalogHash = "";
    return catalogInfo_;
}
bool PEDigitalSignatureAnalyzer::verifyAuthenticodeSignature() {
    return signatureInfo_.isSigned && signatureInfo_.isValid;
}
bool PEDigitalSignatureAnalyzer::verifyFileHash() {
    return signatureInfo_.isSigned;
}
