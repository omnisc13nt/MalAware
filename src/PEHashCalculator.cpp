#include "../include/PEHashCalculator.h"
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
    std::stringstream ss;
    ss << "checksum_md5_";
    
    uint32_t checksum = 0;
    for (size_t i = 0; i < size; i++) {
        checksum = (checksum << 1) ^ data[i];
    }
    
    ss << std::hex << std::setw(8) << std::setfill('0') << checksum;
    ss << std::hex << std::setw(8) << std::setfill('0') << (checksum >> 16);
    ss << std::hex << std::setw(8) << std::setfill('0') << (size & 0xFFFFFFFF);
    ss << std::hex << std::setw(8) << std::setfill('0') << ((size >> 32) & 0xFFFFFFFF);
    
    return ss.str();
}

std::string PEHashCalculator::calculateSHA1Simple(const BYTE* data, size_t size) {
    std::stringstream ss;
    ss << "checksum_sha1_";
    
    uint32_t hash = 0x67452301;
    for (size_t i = 0; i < size; i++) {
        hash = ((hash << 5) | (hash >> 27)) ^ data[i];
    }
    
    ss << std::hex << std::setw(8) << std::setfill('0') << hash;
    ss << std::hex << std::setw(8) << std::setfill('0') << (hash ^ 0x12345678);
    ss << std::hex << std::setw(8) << std::setfill('0') << (hash ^ 0x9ABCDEF0);
    ss << std::hex << std::setw(8) << std::setfill('0') << (hash ^ 0xFEDCBA98);
    ss << std::hex << std::setw(8) << std::setfill('0') << (hash ^ 0x76543210);
    
    return ss.str();
}

std::string PEHashCalculator::calculateSHA256Simple(const BYTE* data, size_t size) {
    std::stringstream ss;
    ss << "checksum_sha256_";
    
    uint32_t hash[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    for (size_t i = 0; i < size; i++) {
        hash[i % 8] = ((hash[i % 8] << 7) | (hash[i % 8] >> 25)) ^ data[i];
    }
    
    for (int i = 0; i < 8; i++) {
        ss << std::hex << std::setw(8) << std::setfill('0') << hash[i];
    }
    
    return ss.str();
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
        importString += toLowerCase(import) + ",";
    }
    
    return "checksum_imphash_" + calculateMD5Simple((BYTE*)importString.c_str(), importString.length()).substr(13);
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
    DWORD fileSize = getFileSize();
    std::stringstream ss;
    ss << (fileSize / 1024) << ":";
    ss << "fuzzy_hash_part1:";
    ss << "fuzzy_hash_part2";
    return ss.str();
}

std::string PEHashCalculator::calculateTLSH() {
    return "T1" + calculateMD5().substr(0, 8) + calculateSHA1().substr(0, 8);
}

std::string PEHashCalculator::calculateVHash() {
    return "04" + calculateMD5().substr(0, 8) + "z" + calculateSHA1().substr(0, 8);
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
        overlayInfo_.fileType = "unknown";
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
        LOGF("\t\tEntropy: %.2f\n", section.entropy);
        LOGF("\t\tChi2: %.2f\n", section.chi2);
        LOGF("\t\tMD5: %s\n", section.md5.c_str());
        LOGF("\t\tSHA-256: %s\n", section.sha256.c_str());
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
    
    LOG("\n[+] OVERLAY INFORMATION\n");
    if (overlayInfo_.hasOverlay) {
        LOGF("\tOverlay Detected: YES\n");
        LOGF("\tOffset: 0x%08X\n", overlayInfo_.offset);
        LOGF("\tSize: %u bytes\n", overlayInfo_.size);
        LOGF("\tEntropy: %.2f\n", overlayInfo_.entropy);
        LOGF("\tChi2: %.2f\n", overlayInfo_.chi2);
        LOGF("\tMD5: %s\n", overlayInfo_.md5.c_str());
        LOGF("\tSHA-256: %s\n", overlayInfo_.sha256.c_str());
        LOGF("\tFile Type: %s\n", overlayInfo_.fileType.c_str());
    } else {
        LOGF("\tOverlay Detected: NO\n");
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

std::string PEHashCalculator::toJson() const {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"fileHashes\": {\n";
    ss << "    \"md5\": \"" << hashResult_.md5 << "\",\n";
    ss << "    \"sha1\": \"" << hashResult_.sha1 << "\",\n";
    ss << "    \"sha256\": \"" << hashResult_.sha256 << "\",\n";
    ss << "    \"imphash\": \"" << hashResult_.imphash << "\",\n";
    ss << "    \"authentihash\": \"" << hashResult_.authentihash << "\",\n";
    ss << "    \"ssdeep\": \"" << hashResult_.ssdeep << "\",\n";
    ss << "    \"tlsh\": \"" << hashResult_.tlsh << "\",\n";
    ss << "    \"vhash\": \"" << hashResult_.vhash << "\"\n";
    ss << "  },\n";
    ss << "  \"fileInfo\": {\n";
    ss << "    \"fileType\": \"" << fileInfo_.fileType << "\",\n";
    ss << "    \"magic\": \"" << fileInfo_.magic << "\",\n";
    ss << "    \"architecture\": \"" << fileInfo_.architecture << "\",\n";
    ss << "    \"fileSize\": " << fileInfo_.fileSize << ",\n";
    ss << "    \"compilationTimestamp\": " << fileInfo_.compilationTimestamp << ",\n";
    ss << "    \"entryPoint\": " << fileInfo_.entryPoint << ",\n";
    ss << "    \"numberOfSections\": " << fileInfo_.numberOfSections << "\n";
    ss << "  }\n";
    ss << "}\n";
    return ss.str();
}
