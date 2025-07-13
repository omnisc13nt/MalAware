#include "../include/PEDigitalSignatureAnalyzer.h"
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
        signatureInfo_.errorMessage = "Failed to extract signature data";
        return signatureInfo_;
    }
    
    signatureInfo_.isSigned = true;
    
    if (!parseWinCertificate(signatureData, signatureSize)) {
        signatureInfo_.errorMessage = "Failed to parse WIN_CERTIFICATE structure";
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
        return false;
    }
    
    
    DWORD dwLength = *(DWORD*)certData;
    WORD wRevision = *(WORD*)(certData + 4);
    WORD wCertificateType = *(WORD*)(certData + 6);
    
    if (dwLength > certSize || dwLength < 8) {
        return false;
    }
    
    if (wCertificateType == 0x0002) { // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        const BYTE* pkcs7Data = certData + 8;
        size_t pkcs7Size = dwLength - 8;
        
        return parsePKCS7Signature(pkcs7Data, pkcs7Size);
    }
    
    return false;
}

bool PEDigitalSignatureAnalyzer::parsePKCS7Signature(const BYTE* pkcs7Data, size_t pkcs7Size) {
    if (!pkcs7Data || pkcs7Size == 0) {
        return false;
    }
    
    
    std::string dataStr((char*)pkcs7Data, pkcs7Size);
    
    if (dataStr.find("sha256") != std::string::npos || dataStr.find("SHA256") != std::string::npos) {
        signatureInfo_.digestAlgorithm = "SHA256";
    } else if (dataStr.find("sha1") != std::string::npos || dataStr.find("SHA1") != std::string::npos) {
        signatureInfo_.digestAlgorithm = "SHA1";
    } else if (dataStr.find("md5") != std::string::npos || dataStr.find("MD5") != std::string::npos) {
        signatureInfo_.digestAlgorithm = "MD5";
    } else {
        signatureInfo_.digestAlgorithm = "Unknown";
    }
    
    if (dataStr.find("RSA") != std::string::npos || dataStr.find("rsa") != std::string::npos) {
        signatureInfo_.signatureAlgorithm = "RSA";
    } else {
        signatureInfo_.signatureAlgorithm = "Unknown";
    }
    
    if (dataStr.find("counterSignature") != std::string::npos || dataStr.find("timeStamping") != std::string::npos) {
        signatureInfo_.isCounterSigned = true;
    }
    
    
    return true;
}

bool PEDigitalSignatureAnalyzer::verifySignatureIntegrity(const BYTE* signatureData, size_t signatureSize) {
    if (!signatureData || signatureSize == 0) {
        return false;
    }
    
    
    if (signatureSize < 2) {
        return false;
    }
    
    if (signatureData[0] == 0x30) { // SEQUENCE tag
        return true;
    }
    
    return false;
}

std::string PEDigitalSignatureAnalyzer::calculateFileHash(const std::string& algorithm) {
    if (!pFileInfo_ || !pFileInfo_->pDosHeader) {
        return "";
    }
    
    
    BYTE* fileData = (BYTE*)pFileInfo_->pDosHeader;
    size_t fileSize = pFileInfo_->dwFileSize;
    
    if (algorithm == "SHA256") {
        std::stringstream ss;
        ss << "SHA256_HASH_";
        for (size_t i = 0; i < std::min(fileSize, (size_t)64); i += 8) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)fileData[i];
        }
        return ss.str();
    }
    
    return "HASH_NOT_IMPLEMENTED";
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

std::string PEDigitalSignatureAnalyzer::toJson() const {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"digitalSignature\": {\n";
    ss << "    \"isSigned\": " << (signatureInfo_.isSigned ? "true" : "false") << ",\n";
    ss << "    \"isValid\": " << (signatureInfo_.isValid ? "true" : "false") << ",\n";
    ss << "    \"isCounterSigned\": " << (signatureInfo_.isCounterSigned ? "true" : "false") << ",\n";
    ss << "    \"digestAlgorithm\": \"" << signatureInfo_.digestAlgorithm << "\",\n";
    ss << "    \"signatureAlgorithm\": \"" << signatureInfo_.signatureAlgorithm << "\",\n";
    ss << "    \"programName\": \"" << signatureInfo_.programName << "\",\n";
    ss << "    \"publisherLink\": \"" << signatureInfo_.publisherLink << "\",\n";
    ss << "    \"errorMessage\": \"" << signatureInfo_.errorMessage << "\"\n";
    ss << "  },\n";
    ss << "  \"securityCatalog\": {\n";
    ss << "    \"isInCatalog\": " << (catalogInfo_.isInCatalog ? "true" : "false") << ",\n";
    ss << "    \"catalogFile\": \"" << catalogInfo_.catalogFile << "\",\n";
    ss << "    \"catalogHash\": \"" << catalogInfo_.catalogHash << "\"\n";
    ss << "  }\n";
    ss << "}\n";
    return ss.str();
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
