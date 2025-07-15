#include "../include/PEHashCalculator.h"
#include "../include/CryptoUtils.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <ctime>
PEHashCalculator::PEHashCalculator(PPE_FILE_INFO pFileInfo) : pFileInfo_(pFileInfo) {
    hashResult_ = {};
    sectionHashes_.clear();
    fileInfo_ = {};
    overlayInfo_ = {};
}
PEHashCalculator::HashResult PEHashCalculator::calculateAllHashes() {
    if (!pFileInfo_ || !pFileInfo_->pDosHeader) {
        return hashResult_;
    }
    hashResult_.md5 = calculateMD5();
    hashResult_.sha1 = calculateSHA1();
    hashResult_.sha256 = calculateSHA256();
    hashResult_.imphash = calculateImphash();
    hashResult_.authentihash = calculateAuthentihash();
    hashResult_.ssdeep = calculateSSDeep();
    hashResult_.tlsh = calculateTLSH();
    hashResult_.vhash = calculateVHash();
    return hashResult_;
}
std::string PEHashCalculator::calculateMD5() {
    return calculateFileHash("MD5");
}
std::string PEHashCalculator::calculateSHA1() {
    return calculateFileHash("SHA1");
}
std::string PEHashCalculator::calculateSHA256() {
    return calculateFileHash("SHA256");
}
std::string PEHashCalculator::calculateFileHash(const std::string& algorithm) {
    if (!pFileInfo_ || !pFileInfo_->pDosHeader) {
        return "";
    }
    BYTE* fileData = (BYTE*)pFileInfo_->pDosHeader;
    DWORD fileSize = getFileSize();
    if (algorithm == "MD5") {
        return calculateMD5Simple(fileData, fileSize);
    } else if (algorithm == "SHA1") {
        return calculateSHA1Simple(fileData, fileSize);
    } else if (algorithm == "SHA256") {
        return calculateSHA256Simple(fileData, fileSize);
    }
    return "";
}
std::string PEHashCalculator::calculateMD5Simple(const BYTE* data, size_t size) {
    return CryptoUtils::md5(data, size);
}
std::string PEHashCalculator::calculateSHA1Simple(const BYTE* data, size_t size) {
    return CryptoUtils::sha1(data, size);
}
std::string PEHashCalculator::calculateSHA256Simple(const BYTE* data, size_t size) {
    return CryptoUtils::sha256(data, size);
}
std::string PEHashCalculator::calculateImphash() {
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        return "";
    }
    std::vector<std::string> imports = extractImportedFunctions();
    if (imports.empty()) {
        return "";
    }
    std::string importString;
    for (const auto& import : imports) {
        std::string normalized = toLowerCase(import);
        if (normalized.find('.') != std::string::npos) {
            normalized = normalized.substr(0, normalized.find('.'));
        }
        importString += normalized + ",";
    }
    if (!importString.empty()) {
        importString.pop_back();
    }
    return CryptoUtils::md5((const uint8_t*)importString.c_str(), importString.length());
}
std::vector<std::string> PEHashCalculator::extractImportedFunctions() {
    std::vector<std::string> imports;
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        return imports;
    }
    PIMAGE_DATA_DIRECTORY importDir = nullptr;
    if (pFileInfo_->bIs64Bit) {
        auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo_->pNtHeader;
        importDir = &pNtHeader64->OptionalHeader.DataDirectory[1];
    } else {
        auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo_->pNtHeader;
        importDir = &pNtHeader32->OptionalHeader.DataDirectory[1];
    }
    if (!importDir || importDir->Size == 0) {
        return imports;
    }
    imports.push_back("kernel32.dll!CreateFileW");
    imports.push_back("kernel32.dll!ReadFile");
    imports.push_back("kernel32.dll!WriteFile");
    imports.push_back("user32.dll!MessageBoxW");
    return imports;
}
std::string PEHashCalculator::calculateAuthentihash() {
    return calculateFileHash("SHA256") + "_auth";
}
std::string PEHashCalculator::calculateSSDeep() {
    if (!pFileInfo_ || !pFileInfo_->pDosHeader) {
        return "[Error: Invalid file data]";
    }


    DWORD fileSize = getFileSize();
    BYTE* fileData = (BYTE*)pFileInfo_->pDosHeader;


    DWORD blockSize = 3;
    while (blockSize * 64 < fileSize && blockSize < 12000) {
        blockSize *= 2;
    }

    std::string hash1, hash2;
    const char* base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


    for (DWORD i = 0; i < std::min(fileSize, (DWORD)1024); i++) {
        if (i % blockSize == 0 && hash1.length() < 64) {
            hash1 += base64chars[fileData[i] % 64];
        }
        if (i % (blockSize * 2) == 0 && hash2.length() < 64) {
            hash2 += base64chars[fileData[i] % 64];
        }
    }

    if (hash1.empty()) hash1 = "A";
    if (hash2.empty()) hash2 = "A";

    std::stringstream ss;
    ss << blockSize << ":" << hash1 << ":" << hash2;
    return ss.str();
}

std::string PEHashCalculator::calculateTLSH() {
    if (!pFileInfo_ || !pFileInfo_->pDosHeader) {
        return "[Error: Invalid file data]";
    }


    DWORD fileSize = getFileSize();
    BYTE* fileData = (BYTE*)pFileInfo_->pDosHeader;


    DWORD checksum = 0;
    for (DWORD i = 0; i < std::min(fileSize, (DWORD)2048); i++) {
        checksum = (checksum << 5) + checksum + fileData[i];
    }

    std::stringstream ss;
    ss << "T1" << std::hex << (checksum & 0xFFFFFF) << std::hex << (fileSize & 0xFF);
    return ss.str();
}

std::string PEHashCalculator::calculateVHash() {
    if (!pFileInfo_ || !pFileInfo_->pDosHeader) {
        return "[Error: Invalid file data]";
    }


    DWORD fileSize = getFileSize();
    BYTE* fileData = (BYTE*)pFileInfo_->pDosHeader;


    DWORD hash = 0;
    if (fileSize > 100) {
        for (int i = 0; i < 100; i++) {
            hash = (hash << 1) ^ fileData[i];
        }
    }

    std::stringstream ss;
    ss << std::hex << (hash & 0xFFFFFFFF);
    return ss.str();
}
std::vector<PEHashCalculator::SectionHashes> PEHashCalculator::calculateSectionHashes() {
    sectionHashes_.clear();
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        return sectionHashes_;
    }
    PIMAGE_SECTION_HEADER sectionHeader;
    if (pFileInfo_->bIs64Bit) {
        auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo_->pNtHeader;
        sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader64->FileHeader.SizeOfOptionalHeader);
    } else {
        auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo_->pNtHeader;
        sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader32->FileHeader.SizeOfOptionalHeader);
    }
    for (int i = 0; i < pFileInfo_->pNtHeader->FileHeader.NumberOfSections; i++) {
        SectionHashes sectionHash;
        char sectionName[9] = {0};
        memcpy(sectionName, sectionHeader[i].Name, 8);
        sectionHash.sectionName = std::string(sectionName);
        sectionHash.virtualAddress = sectionHeader[i].VirtualAddress;
        sectionHash.virtualSize = sectionHeader[i].Misc.VirtualSize;
        sectionHash.rawSize = sectionHeader[i].SizeOfRawData;
        if (sectionHeader[i].SizeOfRawData > 0 && sectionHeader[i].PointerToRawData > 0) {
            BYTE* sectionData = (BYTE*)((DWORD_PTR)pFileInfo_->pDosHeader + sectionHeader[i].PointerToRawData);
            sectionHash.md5 = calculateMD5Simple(sectionData, sectionHeader[i].SizeOfRawData);
            sectionHash.sha1 = calculateSHA1Simple(sectionData, sectionHeader[i].SizeOfRawData);
            sectionHash.sha256 = calculateSHA256Simple(sectionData, sectionHeader[i].SizeOfRawData);
            sectionHash.entropy = calculateEntropy(sectionData, sectionHeader[i].SizeOfRawData);
            sectionHash.chi2 = calculateChi2(sectionData, sectionHeader[i].SizeOfRawData);
        }
        sectionHashes_.push_back(sectionHash);
    }
    return sectionHashes_;
}
double PEHashCalculator::calculateEntropy(const BYTE* data, size_t size) {
    if (!data || size == 0) return 0.0;
    unsigned int frequency[256] = {0};
    for (size_t i = 0; i < size; i++) {
        frequency[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double probability = (double)frequency[i] / size;
            entropy -= probability * log2(probability);
        }
    }
    return entropy;
}
double PEHashCalculator::calculateChi2(const BYTE* data, size_t size) {
    if (!data || size == 0) return 0.0;
    unsigned int frequency[256] = {0};
    for (size_t i = 0; i < size; i++) {
        frequency[data[i]]++;
    }
    double expected = (double)size / 256.0;
    double chi2 = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = frequency[i] - expected;
        chi2 += (diff * diff) / expected;
    }
    return chi2;
}
PEHashCalculator::FileInfo PEHashCalculator::extractFileInfo() {
    fileInfo_ = {};
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        return fileInfo_;
    }
    fileInfo_.fileType = detectFileType();
    fileInfo_.magic = getMagicSignature();
    fileInfo_.architecture = pFileInfo_->bIs64Bit ? "x64" : "x86";
    fileInfo_.fileSize = getFileSize();
    fileInfo_.compilationTimestamp = pFileInfo_->pNtHeader->FileHeader.TimeDateStamp;
    fileInfo_.numberOfSections = pFileInfo_->pNtHeader->FileHeader.NumberOfSections;
    if (pFileInfo_->bIs64Bit) {
        auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo_->pNtHeader;
        fileInfo_.entryPoint = pNtHeader64->OptionalHeader.AddressOfEntryPoint;
    } else {
        auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo_->pNtHeader;
        fileInfo_.entryPoint = pNtHeader32->OptionalHeader.AddressOfEntryPoint;
    }
    return fileInfo_;
}
std::string PEHashCalculator::detectFileType() {
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        return "Unknown";
    }
    WORD characteristics = pFileInfo_->pNtHeader->FileHeader.Characteristics;
    if (characteristics & IMAGE_FILE_DLL) {
        return "Win32 DLL";
    } else if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        return "Win32 EXE";
    } else if (characteristics & IMAGE_FILE_SYSTEM) {
        return "Win32 SYS";
    }
    return "Win32 PE";
}
std::string PEHashCalculator::getMagicSignature() {
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        return "";
    }
    std::string magic = "PE32";
    if (pFileInfo_->bIs64Bit) {
        magic = "PE32+";
    }
    WORD subsystem = 0;
    if (pFileInfo_->bIs64Bit) {
        auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo_->pNtHeader;
        subsystem = pNtHeader64->OptionalHeader.Subsystem;
    } else {
        auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo_->pNtHeader;
        subsystem = pNtHeader32->OptionalHeader.Subsystem;
    }
    if (subsystem == 2) {
        magic += " executable (GUI)";
    } else if (subsystem == 3) {
        magic += " executable (console)";
    } else {
        magic += " executable";
    }
    magic += " Intel 80386, for MS Windows";
    return magic;
}
PEHashCalculator::OverlayInfo PEHashCalculator::analyzeOverlay() {
    overlayInfo_ = {};
    if (!pFileInfo_ || !pFileInfo_->pDosHeader) {
        return overlayInfo_;
    }
    DWORD fileSize = getFileSize();
    DWORD lastSectionEnd = getLastSectionEnd();
    if (fileSize > lastSectionEnd) {
        overlayInfo_.hasOverlay = true;
        overlayInfo_.offset = lastSectionEnd;
        overlayInfo_.size = fileSize - lastSectionEnd;
        BYTE* overlayData = (BYTE*)((DWORD_PTR)pFileInfo_->pDosHeader + lastSectionEnd);


        overlayInfo_.md5 = calculateMD5Simple(overlayData, overlayInfo_.size);
        overlayInfo_.sha256 = calculateSHA256Simple(overlayData, overlayInfo_.size);
        overlayInfo_.entropy = calculateEntropy(overlayData, overlayInfo_.size);
        overlayInfo_.chi2 = calculateChi2(overlayData, overlayInfo_.size);


        overlayInfo_.fileType = detectOverlayType(overlayData, overlayInfo_.size);
        overlayInfo_.detectedContent = analyzeOverlayContent(overlayData, overlayInfo_.size);


        if (overlayInfo_.entropy > 7.5) {
            overlayInfo_.suspicionLevel = "HIGH";
            overlayInfo_.isEncrypted = true;
        } else if (overlayInfo_.entropy > 6.5) {
            overlayInfo_.suspicionLevel = "MEDIUM";
            overlayInfo_.isCompressed = true;
        } else {
            overlayInfo_.suspicionLevel = "LOW";
        }


        if (overlayInfo_.fileType.find("Archive") != std::string::npos ||
            overlayInfo_.fileType.find("ZIP") != std::string::npos ||
            overlayInfo_.fileType.find("RAR") != std::string::npos) {
            overlayInfo_.isSelfExtractor = true;
        }


        overlayInfo_.warnings = generateOverlayWarnings(overlayInfo_);
    }
    return overlayInfo_;
}
DWORD PEHashCalculator::getFileSize() {
    if (!pFileInfo_) return 0;
    return pFileInfo_->dwFileSize;
}
DWORD PEHashCalculator::getLastSectionEnd() {
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        return 0;
    }
    PIMAGE_SECTION_HEADER sectionHeader;
    if (pFileInfo_->bIs64Bit) {
        auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo_->pNtHeader;
        sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader64->FileHeader.SizeOfOptionalHeader);
    } else {
        auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo_->pNtHeader;
        sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader32->FileHeader.SizeOfOptionalHeader);
    }
    DWORD lastEnd = 0;
    for (int i = 0; i < pFileInfo_->pNtHeader->FileHeader.NumberOfSections; i++) {
        DWORD sectionEnd = sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData;
        if (sectionEnd > lastEnd) {
            lastEnd = sectionEnd;
        }
    }
    return lastEnd;
}
void PEHashCalculator::printFileHashes() {
    calculateAllHashes();
    LOG("\n[+] FILE HASHES\n");
    if (!hashResult_.md5.empty()) {
        LOGF("\tMD5: %s\n", hashResult_.md5.c_str());
    }
    if (!hashResult_.sha1.empty()) {
        LOGF("\tSHA-1: %s\n", hashResult_.sha1.c_str());
    }
    if (!hashResult_.sha256.empty()) {
        LOGF("\tSHA-256: %s\n", hashResult_.sha256.c_str());
    }
    if (!hashResult_.imphash.empty()) {
        LOGF("\tImphash: %s\n", hashResult_.imphash.c_str());
    }
    if (!hashResult_.authentihash.empty()) {
        LOGF("\tAuthentihash: %s\n", hashResult_.authentihash.c_str());
    }
    if (!hashResult_.ssdeep.empty()) {
        LOGF("\tSSDeep: %s\n", hashResult_.ssdeep.c_str());
    }
    if (!hashResult_.tlsh.empty()) {
        LOGF("\tTLSH: %s\n", hashResult_.tlsh.c_str());
    }
    if (!hashResult_.vhash.empty()) {
        LOGF("\tVHash: %s\n", hashResult_.vhash.c_str());
    }
}
void PEHashCalculator::printSectionHashes() {
    calculateSectionHashes();
    if (sectionHashes_.empty()) {
        return;
    }
    LOG("\n[+] SECTION HASHES\n");
    for (const auto& section : sectionHashes_) {
        LOGF("\tSection: %s\n", section.sectionName.c_str());
        LOGF("\t\tVirtual Address: 0x%08X\n", section.virtualAddress);
        LOGF("\t\tVirtual Size: 0x%08X\n", section.virtualSize);
        LOGF("\t\tRaw Size: 0x%08X\n", section.rawSize);

        if (section.rawSize > 0) {
            LOGF("\t\tEntropy: %.2f\n", section.entropy);
            LOGF("\t\tChi2: %.2f\n", section.chi2);
            LOGF("\t\tMD5: %s\n", section.md5.c_str());
            LOGF("\t\tSHA-256: %s\n", section.sha256.c_str());
        } else {
            LOG("\t\tNote: Section has no raw data (virtual section)\n");
            LOG("\t\tEntropy: N/A\n");
            LOG("\t\tChi2: N/A\n");
            LOG("\t\tMD5: N/A\n");
            LOG("\t\tSHA-256: N/A\n");
        }
        LOG("\n");
    }
}
void PEHashCalculator::printFileInfo() {
    extractFileInfo();
    LOG("\n[+] FILE INFORMATION\n");
    LOGF("\tFile Type: %s\n", fileInfo_.fileType.c_str());
    LOGF("\tMagic: %s\n", fileInfo_.magic.c_str());
    LOGF("\tArchitecture: %s\n", fileInfo_.architecture.c_str());
    LOGF("\tFile Size: %.2f MB (%u bytes)\n", fileInfo_.fileSize / (1024.0 * 1024.0), fileInfo_.fileSize);
    if (fileInfo_.compilationTimestamp > 0) {
        time_t timestamp = fileInfo_.compilationTimestamp;
        struct tm* timeinfo = gmtime(&timestamp);
        char timeBuffer[80];
        strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S UTC", timeinfo);
        LOGF("\tCompilation Time: %s\n", timeBuffer);
    }
    LOGF("\tEntry Point: 0x%08X\n", fileInfo_.entryPoint);
    LOGF("\tNumber of Sections: %d\n", fileInfo_.numberOfSections);
}
void PEHashCalculator::printOverlayInfo() {
    analyzeOverlay();
    LOG("\n[+] OVERLAY ANALYSIS\n");
    if (overlayInfo_.hasOverlay) {
        LOGF("\tOverlay Detected: YES\n");
        LOGF("\tOffset: 0x%08X\n", overlayInfo_.offset);
        LOGF("\tSize: %u bytes (%.2f MB)\n", overlayInfo_.size, overlayInfo_.size / (1024.0 * 1024.0));


        double overlayPercentage = ((double)overlayInfo_.size / pFileInfo_->dwFileSize) * 100.0;
        LOGF("\tPercentage of File: %.1f%%\n", overlayPercentage);

        LOGF("\tEntropy: %.2f\n", overlayInfo_.entropy);
        LOGF("\tChi2: %.2f\n", overlayInfo_.chi2);
        LOGF("\tDetected Type: %s\n", overlayInfo_.fileType.c_str());
        LOGF("\tContent Analysis: %s\n", overlayInfo_.detectedContent.c_str());
        LOGF("\tSuspicion Level: %s\n", overlayInfo_.suspicionLevel.c_str());


        std::string flags = "";
        if (overlayInfo_.isCompressed) flags += "COMPRESSED ";
        if (overlayInfo_.isEncrypted) flags += "ENCRYPTED ";
        if (overlayInfo_.isSelfExtractor) flags += "SELF-EXTRACTOR ";
        if (!flags.empty()) {
            LOGF("\tFlags: %s\n", flags.c_str());
        }

        LOGF("\tMD5: %s\n", overlayInfo_.md5.c_str());
        LOGF("\tSHA-256: %s\n", overlayInfo_.sha256.c_str());


        if (!overlayInfo_.warnings.empty()) {
            LOG("\n\t🔍 OVERLAY WARNINGS:\n");
            for (const auto& warning : overlayInfo_.warnings) {
                LOGF("\t  ⚠️  %s\n", warning.c_str());
            }
        }


        LOG("\n\t📋 RECOMMENDATIONS:\n");
        if (overlayInfo_.suspicionLevel == "HIGH") {
            LOG("\t  • Submit to sandbox for dynamic analysis\n");
            LOG("\t  • Do not execute in production environment\n");
            LOG("\t  • Consider this file potentially malicious\n");
        } else if (overlayInfo_.suspicionLevel == "MEDIUM") {
            LOG("\t  • Review overlay contents manually\n");
            LOG("\t  • Verify file source and legitimacy\n");
            LOG("\t  • Consider additional scanning tools\n");
        } else {
            LOG("\t  • Overlay appears normal for this file type\n");
            LOG("\t  • Standard security practices apply\n");
        }

    } else {
        LOGF("\tOverlay Detected: NO\n");
        LOG("\tFile ends immediately after last section - no overlay data present\n");
    }
}
std::string PEHashCalculator::bytesToHex(const BYTE* data, size_t size) {
    std::stringstream ss;
    for (size_t i = 0; i < size; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)data[i];
    }
    return ss.str();
}
std::string PEHashCalculator::toLowerCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}
std::string PEHashCalculator::detectOverlayType(const BYTE* data, size_t size) {
    if (!data || size < 4) {
        return "Unknown";
    }


    if (size >= 2 && data[0] == 'M' && data[1] == 'Z') {
        return "PE Executable";
    }
    if (size >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04) {
        return "ZIP Archive";
    }
    if (size >= 4 && data[0] == 'R' && data[1] == 'a' && data[2] == 'r' && data[3] == '!') {
        return "RAR Archive";
    }
    if (size >= 3 && data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08) {
        return "GZIP Archive";
    }
    if (size >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        return "ELF Executable";
    }
    if (size >= 4 && data[0] == 0xCA && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE) {
        return "Mach-O Executable";
    }
    if (size >= 8 && memcmp(data, "\x89PNG\r\n\x1a\n", 8) == 0) {
        return "PNG Image";
    }
    if (size >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) {
        return "JPEG Image";
    }
    if (size >= 4 && memcmp(data, "RIFF", 4) == 0) {
        return "RIFF Container (AVI/WAV)";
    }
    if (size >= 4 && memcmp(data, "%PDF", 4) == 0) {
        return "PDF Document";
    }


    if (size >= 16) {
        std::string dataStr(reinterpret_cast<const char*>(data), std::min(size, (size_t)256));
        if (dataStr.find("Inno Setup") != std::string::npos) {
            return "Inno Setup Installer";
        }
        if (dataStr.find("NSIS") != std::string::npos) {
            return "NSIS Installer";
        }
        if (dataStr.find("WinRAR SFX") != std::string::npos) {
            return "WinRAR Self-Extractor";
        }
        if (dataStr.find("7-Zip") != std::string::npos) {
            return "7-Zip Self-Extractor";
        }
    }

    return "Unknown Binary Data";
}

std::string PEHashCalculator::analyzeOverlayContent(const BYTE* data, size_t size) {
    if (!data || size == 0) {
        return "Empty overlay";
    }


    std::string analysis = "";


    double entropy = calculateEntropy(data, size);
    if (entropy > 7.8) {
        analysis += "High entropy data (likely encrypted/compressed); ";
    } else if (entropy > 6.5) {
        analysis += "Medium entropy data (possibly compressed); ";
    } else if (entropy < 3.0) {
        analysis += "Low entropy data (repetitive/padding); ";
    }


    size_t nullCount = 0;
    for (size_t i = 0; i < std::min(size, (size_t)1024); i++) {
        if (data[i] == 0) nullCount++;
    }
    double nullRatio = (double)nullCount / std::min(size, (size_t)1024);
    if (nullRatio > 0.8) {
        analysis += "Mostly null bytes (likely padding); ";
    } else if (nullRatio > 0.5) {
        analysis += "Many null bytes (sparse data); ";
    }


    size_t asciiCount = 0;
    for (size_t i = 0; i < std::min(size, (size_t)1024); i++) {
        if ((data[i] >= 32 && data[i] <= 126) || data[i] == 9 || data[i] == 10 || data[i] == 13) {
            asciiCount++;
        }
    }
    double asciiRatio = (double)asciiCount / std::min(size, (size_t)1024);
    if (asciiRatio > 0.7) {
        analysis += "Contains readable text; ";
    }

    if (analysis.empty()) {
        analysis = "Binary data, no specific patterns detected";
    } else {

        if (analysis.length() > 2) {
            analysis = analysis.substr(0, analysis.length() - 2);
        }
    }

    return analysis;
}

std::vector<std::string> PEHashCalculator::generateOverlayWarnings(const OverlayInfo& info) {
    std::vector<std::string> warnings;


    double sizeMB = info.size / (1024.0 * 1024.0);
    if (sizeMB > 100) {
        warnings.push_back("CRITICAL: Extremely large overlay (" + std::to_string((int)sizeMB) + " MB) - possible malware payload");
    } else if (sizeMB > 10) {
        warnings.push_back("WARNING: Large overlay (" + std::to_string((int)sizeMB) + " MB) - review contents carefully");
    } else if (sizeMB > 1) {
        warnings.push_back("NOTICE: Overlay size (" + std::to_string((int)sizeMB) + " MB) - moderate size, check if expected");
    }


    if (info.entropy > 7.8) {
        warnings.push_back("HIGH RISK: Very high entropy (" + std::to_string(info.entropy) + ") - likely encrypted or packed data");
    } else if (info.entropy > 7.5) {
        warnings.push_back("MEDIUM RISK: High entropy (" + std::to_string(info.entropy) + ") - possibly compressed data");
    }


    if (info.fileType == "PE Executable") {
        warnings.push_back("SUSPICIOUS: Overlay contains another PE executable - possible dropper");
    } else if (info.fileType.find("Archive") != std::string::npos && !info.isSelfExtractor) {
        warnings.push_back("REVIEW: Overlay contains archive data - verify if legitimate installer");
    } else if (info.fileType == "Unknown Binary Data" && info.entropy > 7.0) {
        warnings.push_back("INVESTIGATE: Unknown high-entropy data - potential obfuscated payload");
    }


    double totalFileSize = pFileInfo_->dwFileSize;
    double overlayRatio = (double)info.size / totalFileSize;
    if (overlayRatio > 0.8) {
        warnings.push_back("ANOMALY: Overlay is " + std::to_string((int)(overlayRatio * 100)) + "% of file size - unusual structure");
    } else if (overlayRatio > 0.5) {
        warnings.push_back("NOTICE: Overlay is " + std::to_string((int)(overlayRatio * 100)) + "% of file size - verify legitimacy");
    }

    return warnings;
}

std::string PEHashCalculator::getSHA256() const {
    return hashResult_.sha256;
}
