#include "../include/PEDebugInfoAnalyzer.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <ctime>
PEDebugInfoAnalyzer::PEDebugInfoAnalyzer(PPE_FILE_INFO pFileInfo) : pFileInfo_(pFileInfo) {
    debugInfo_ = {};
}
PEDebugInfoAnalyzer::DebugInfo PEDebugInfoAnalyzer::analyzeDebugInfo() {
    debugInfo_ = {};
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        return debugInfo_;
    }
    debugInfo_.debugDirectories = parseDebugDirectories();
    debugInfo_.hasDebugInfo = !debugInfo_.debugDirectories.empty();
    for (const auto& entry : debugInfo_.debugDirectories) {
        if (entry.type == IMAGE_DEBUG_TYPE_CODEVIEW) {
            BYTE* data = nullptr;
            size_t size = 0;
            if (extractDebugData(entry, &data, &size)) {
                debugInfo_.codeViewInfo = parseCodeViewInfo(data, size);
            }
        }
    }
    debugInfo_.compiledWith = identifyCompiler();
    debugInfo_.buildEnvironment = extractBuildEnvironment();
    debugInfo_.hasSymbols = hasSymbolTable();
    debugInfo_.isOptimized = (debugInfo_.debugDirectories.empty() || 
                             debugInfo_.codeViewInfo.pdbPath.empty());
    return debugInfo_;
}
std::vector<PEDebugInfoAnalyzer::DebugDirectoryEntry> PEDebugInfoAnalyzer::parseDebugDirectories() {
    std::vector<DebugDirectoryEntry> entries;
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        return entries;
    }
    PIMAGE_DATA_DIRECTORY debugDir = nullptr;
    if (pFileInfo_->bIs64Bit) {
        auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo_->pNtHeader;
        if (pNtHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            debugDir = &pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        }
    } else {
        auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo_->pNtHeader;
        if (pNtHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            debugDir = &pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        }
    }
    if (!debugDir || debugDir->Size == 0) {
        return entries;
    }
    DWORD entryCount = debugDir->Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    DWORD fileOffset = 0;
    bool found = false;
    PIMAGE_SECTION_HEADER sectionHeader;
    if (pFileInfo_->bIs64Bit) {
        auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo_->pNtHeader;
        sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader64->FileHeader.SizeOfOptionalHeader);
    } else {
        auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo_->pNtHeader;
        sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader32->FileHeader.SizeOfOptionalHeader);
    }
    for (int i = 0; i < pFileInfo_->pNtHeader->FileHeader.NumberOfSections; i++) {
        if (debugDir->VirtualAddress >= sectionHeader[i].VirtualAddress &&
            debugDir->VirtualAddress < sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData) {
            fileOffset = sectionHeader[i].PointerToRawData + 
                        (debugDir->VirtualAddress - sectionHeader[i].VirtualAddress);
            found = true;
            break;
        }
    }
    if (!found) {
        return entries;
    }
    PIMAGE_DEBUG_DIRECTORY debugEntries = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)pFileInfo_->pDosHeader + fileOffset);
    for (DWORD i = 0; i < entryCount; i++) {
        DebugDirectoryEntry entry;
        entry.characteristics = debugEntries[i].Characteristics;
        entry.timeDateStamp = debugEntries[i].TimeDateStamp;
        entry.majorVersion = debugEntries[i].MajorVersion;
        entry.minorVersion = debugEntries[i].MinorVersion;
        entry.type = debugEntries[i].Type;
        entry.sizeOfData = debugEntries[i].SizeOfData;
        entry.addressOfRawData = debugEntries[i].AddressOfRawData;
        entry.pointerToRawData = debugEntries[i].PointerToRawData;
        entry.typeName = getDebugTypeName(entry.type);
        entries.push_back(entry);
    }
    return entries;
}
PEDebugInfoAnalyzer::CodeViewInfo PEDebugInfoAnalyzer::parseCodeViewInfo(const BYTE* data, size_t size) {
    CodeViewInfo info = {};
    if (!data || size < 4) {
        return info;
    }
    DWORD signature = *(DWORD*)data;
    if (signature == 0x53445352) { 
        info.isValid = parseCodeViewPDB70(data, size);
        info.signature = "RSDS";
    } else if (signature == 0x3031424E) { 
        info.isValid = parseCodeViewPDB20(data, size);
        info.signature = "NB10";
    } else if (signature == 0x3131424E) { 
        info.isValid = parseCodeViewPDB20(data, size);
        info.signature = "NB11";
    } else {
        info.signature = "Unknown";
        info.isValid = false;
    }
    return info;
}
bool PEDebugInfoAnalyzer::parseCodeViewPDB70(const BYTE* data, size_t size) {
    if (size < 24) { 
        return false;
    }
    const BYTE* guidBytes = data + 4;
    debugInfo_.codeViewInfo.guid = formatGuid(guidBytes);
    debugInfo_.codeViewInfo.age = *(DWORD*)(data + 20);
    if (size > 24) {
        const char* pdbPath = (const char*)(data + 24);
        size_t maxLen = size - 24;
        size_t pathLen = strnlen(pdbPath, maxLen);
        if (pathLen > 0 && pathLen < maxLen) {
            debugInfo_.codeViewInfo.pdbPath = std::string(pdbPath, pathLen);
        }
    }
    return true;
}
bool PEDebugInfoAnalyzer::parseCodeViewPDB20(const BYTE* data, size_t size) {
    if (size < 16) { 
        return false;
    }
    DWORD timestamp = *(DWORD*)(data + 8);
    (void)timestamp; // Suppress unused variable warning
    debugInfo_.codeViewInfo.age = *(DWORD*)(data + 12);
    if (size > 16) {
        const char* pdbPath = (const char*)(data + 16);
        size_t maxLen = size - 16;
        size_t pathLen = strnlen(pdbPath, maxLen);
        if (pathLen > 0 && pathLen < maxLen) {
            debugInfo_.codeViewInfo.pdbPath = std::string(pdbPath, pathLen);
        }
    }
    return true;
}
std::string PEDebugInfoAnalyzer::identifyCompiler() {
    std::string compiler = "Unknown";
    if (!debugInfo_.codeViewInfo.pdbPath.empty()) {
        const std::string& pdbPath = debugInfo_.codeViewInfo.pdbPath;
        if (pdbPath.find("vc") != std::string::npos || 
            pdbPath.find("msvc") != std::string::npos || 
            pdbPath.find("Visual Studio") != std::string::npos) {
            compiler = "Microsoft Visual C++";
        } else if (pdbPath.find("mingw") != std::string::npos) {
            compiler = "MinGW";
        } else if (pdbPath.find("gcc") != std::string::npos) {
            compiler = "GCC";
        } else if (pdbPath.find("clang") != std::string::npos) {
            compiler = "Clang";
        }
    }
    if (hasRichHeader()) {
        std::string richInfo = parseRichHeader();
        if (!richInfo.empty()) {
            compiler += " (Rich Header: " + richInfo + ")";
        }
    }
    return compiler;
}
std::string PEDebugInfoAnalyzer::extractBuildEnvironment() {
    std::string environment = "Unknown";
    if (!debugInfo_.codeViewInfo.pdbPath.empty()) {
        const std::string& pdbPath = debugInfo_.codeViewInfo.pdbPath;
        size_t lastSlash = pdbPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            environment = pdbPath.substr(0, lastSlash);
        }
    }
    return environment;
}
bool PEDebugInfoAnalyzer::hasSymbolTable() {
    if (!pFileInfo_ || !pFileInfo_->pNtHeader) {
        return false;
    }
    return (pFileInfo_->pNtHeader->FileHeader.NumberOfSymbols > 0 && 
            pFileInfo_->pNtHeader->FileHeader.PointerToSymbolTable != 0);
}
bool PEDebugInfoAnalyzer::hasRichHeader() {
    return (findRichHeader() != nullptr);
}
BYTE* PEDebugInfoAnalyzer::findRichHeader() {
    if (!pFileInfo_ || !pFileInfo_->pDosHeader) {
        return nullptr;
    }
    DWORD ntHeaderOffset = pFileInfo_->pDosHeader->e_lfanew;
    BYTE* searchStart = (BYTE*)pFileInfo_->pDosHeader + sizeof(IMAGE_DOS_HEADER);
    BYTE* searchEnd = (BYTE*)pFileInfo_->pDosHeader + ntHeaderOffset;
    for (BYTE* ptr = searchStart; ptr < searchEnd - 4; ptr++) {
        if (*(DWORD*)ptr == 0x68636952) { 
            return ptr;
        }
    }
    return nullptr;
}
std::string PEDebugInfoAnalyzer::parseRichHeader() {
    BYTE* richPtr = findRichHeader();
    if (!richPtr) {
        return "";
    }
    return "Rich header present";
}
bool PEDebugInfoAnalyzer::extractDebugData(const DebugDirectoryEntry& entry, BYTE** data, size_t* size) {
    if (!pFileInfo_ || !data || !size) {
        return false;
    }
    if (entry.sizeOfData == 0 || entry.pointerToRawData == 0) {
        return false;
    }
    *data = (BYTE*)((DWORD_PTR)pFileInfo_->pDosHeader + entry.pointerToRawData);
    *size = entry.sizeOfData;
    return true;
}
void PEDebugInfoAnalyzer::printDebugInfo() {
    LOG("\n[+] DEBUG INFORMATION ANALYSIS\n");
    if (!debugInfo_.hasDebugInfo) {
        LOG("\tNo debug information found\n");
        LOG("\tNote: Debug information includes symbols, source code references, and development metadata.\n");
        LOG("\t      Absence is normal for release builds and may indicate:\n");
        LOG("\t      - Stripped release build (common for deployed software)\n");
        LOG("\t      - Compiled without debug symbols for size optimization\n");
        LOG("\t      - Not relevant for malware analysis unless reversing is needed\n");
        return;
    }
    LOGF("\tHas Debug Info: %s\n", debugInfo_.hasDebugInfo ? "YES" : "NO");
    LOGF("\tHas Symbols: %s\n", debugInfo_.hasSymbols ? "YES" : "NO");
    LOGF("\tIs Optimized: %s\n", debugInfo_.isOptimized ? "YES" : "NO");
    LOGF("\tCompiled With: %s\n", debugInfo_.compiledWith.c_str());
    if (!debugInfo_.buildEnvironment.empty() && debugInfo_.buildEnvironment != "Unknown") {
        LOGF("\tBuild Environment: %s\n", debugInfo_.buildEnvironment.c_str());
    }
}
void PEDebugInfoAnalyzer::printDebugDirectories() {
    if (debugInfo_.debugDirectories.empty()) {
        LOG("\tNo debug directories found\n");
        return;
    }
    LOG("\n[+] DEBUG DIRECTORIES\n");
    for (size_t i = 0; i < debugInfo_.debugDirectories.size(); i++) {
        const auto& entry = debugInfo_.debugDirectories[i];
        LOGF("\tDebug Directory %zu:\n", i + 1);
        LOGF("\t\tType: %s (%d)\n", entry.typeName.c_str(), entry.type);
        LOGF("\t\tSize: %d bytes\n", entry.sizeOfData);
        LOGF("\t\tTimestamp: %s\n", formatTimestamp(entry.timeDateStamp).c_str());
        LOGF("\t\tVersion: %d.%d\n", entry.majorVersion, entry.minorVersion);
        LOGF("\t\tRaw Data Offset: 0x%08X\n", entry.pointerToRawData);
    }
}
void PEDebugInfoAnalyzer::printCodeViewInfo() {
    if (!debugInfo_.codeViewInfo.isValid) {
        LOG("\tNo CodeView information found\n");
        return;
    }
    LOG("\n[+] CODEVIEW INFORMATION\n");
    LOGF("\tSignature: %s\n", debugInfo_.codeViewInfo.signature.c_str());
    if (!debugInfo_.codeViewInfo.pdbPath.empty()) {
        LOGF("\tPDB Path: %s\n", debugInfo_.codeViewInfo.pdbPath.c_str());
    }
    if (!debugInfo_.codeViewInfo.guid.empty()) {
        LOGF("\tGUID: %s\n", debugInfo_.codeViewInfo.guid.c_str());
    }
    if (debugInfo_.codeViewInfo.age > 0) {
        LOGF("\tAge: %d\n", debugInfo_.codeViewInfo.age);
    }
}
void PEDebugInfoAnalyzer::printRichHeaderInfo() {
    if (!hasRichHeader()) {
        LOG("\tNo Rich header found\n");
        return;
    }
    LOG("\n[+] RICH HEADER INFORMATION\n");
    std::string richInfo = parseRichHeader();
    if (!richInfo.empty()) {
        LOGF("\tRich Header: %s\n", richInfo.c_str());
    }
}
std::string PEDebugInfoAnalyzer::getDebugTypeName(DWORD type) {
    switch (type) {
        case IMAGE_DEBUG_TYPE_UNKNOWN: return "Unknown";
        case IMAGE_DEBUG_TYPE_COFF: return "COFF";
        case IMAGE_DEBUG_TYPE_CODEVIEW: return "CodeView";
        case IMAGE_DEBUG_TYPE_FPO: return "FPO";
        case IMAGE_DEBUG_TYPE_MISC: return "Misc";
        case IMAGE_DEBUG_TYPE_EXCEPTION: return "Exception";
        case IMAGE_DEBUG_TYPE_FIXUP: return "Fixup";
        case IMAGE_DEBUG_TYPE_OMAP_TO_SRC: return "OMAP to Source";
        case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: return "OMAP from Source";
        case IMAGE_DEBUG_TYPE_BORLAND: return "Borland";
        case IMAGE_DEBUG_TYPE_RESERVED10: return "Reserved";
        case IMAGE_DEBUG_TYPE_CLSID: return "CLSID";
        case IMAGE_DEBUG_TYPE_VC_FEATURE: return "VC Feature";
        case IMAGE_DEBUG_TYPE_POGO: return "POGO";
        case IMAGE_DEBUG_TYPE_ILTCG: return "ILTCG";
        case IMAGE_DEBUG_TYPE_MPX: return "MPX";
        case IMAGE_DEBUG_TYPE_REPRO: return "Reproducible";
        default: return "Unknown Type";
    }
}
std::string PEDebugInfoAnalyzer::formatGuid(const BYTE* guidBytes) {
    if (!guidBytes) {
        return "";
    }
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    DWORD* d1 = (DWORD*)guidBytes;
    WORD* w1 = (WORD*)(guidBytes + 4);
    WORD* w2 = (WORD*)(guidBytes + 6);
    ss << "{" << std::setw(8) << *d1 << "-"
       << std::setw(4) << *w1 << "-"
       << std::setw(4) << *w2 << "-"
       << std::setw(2) << (unsigned int)guidBytes[8] << std::setw(2) << (unsigned int)guidBytes[9] << "-";
    for (int i = 10; i < 16; i++) {
        ss << std::setw(2) << (unsigned int)guidBytes[i];
    }
    ss << "}";
    return ss.str();
}
std::string PEDebugInfoAnalyzer::formatTimestamp(DWORD timestamp) {
    if (timestamp == 0) {
        return "Not set";
    }
    time_t time = timestamp;
    struct tm* timeinfo = localtime(&time);
    std::stringstream ss;
    ss << std::put_time(timeinfo, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}
std::string PEDebugInfoAnalyzer::toJson() const {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"debugInfo\": {\n";
    ss << "    \"hasDebugInfo\": " << (debugInfo_.hasDebugInfo ? "true" : "false") << ",\n";
    ss << "    \"hasSymbols\": " << (debugInfo_.hasSymbols ? "true" : "false") << ",\n";
    ss << "    \"isOptimized\": " << (debugInfo_.isOptimized ? "true" : "false") << ",\n";
    ss << "    \"compiledWith\": \"" << debugInfo_.compiledWith << "\",\n";
    ss << "    \"buildEnvironment\": \"" << debugInfo_.buildEnvironment << "\",\n";
    ss << "    \"debugDirectories\": [\n";
    for (size_t i = 0; i < debugInfo_.debugDirectories.size(); i++) {
        const auto& entry = debugInfo_.debugDirectories[i];
        ss << "      {\n";
        ss << "        \"type\": " << entry.type << ",\n";
        ss << "        \"typeName\": \"" << entry.typeName << "\",\n";
        ss << "        \"size\": " << entry.sizeOfData << ",\n";
        ss << "        \"timestamp\": " << entry.timeDateStamp << ",\n";
        ss << "        \"version\": \"" << entry.majorVersion << "." << entry.minorVersion << "\"\n";
        ss << "      }";
        if (i < debugInfo_.debugDirectories.size() - 1) ss << ",";
        ss << "\n";
    }
    ss << "    ],\n";
    ss << "    \"codeViewInfo\": {\n";
    ss << "      \"isValid\": " << (debugInfo_.codeViewInfo.isValid ? "true" : "false") << ",\n";
    ss << "      \"signature\": \"" << debugInfo_.codeViewInfo.signature << "\",\n";
    ss << "      \"pdbPath\": \"" << debugInfo_.codeViewInfo.pdbPath << "\",\n";
    ss << "      \"guid\": \"" << debugInfo_.codeViewInfo.guid << "\",\n";
    ss << "      \"age\": " << debugInfo_.codeViewInfo.age << "\n";
    ss << "    }\n";
    ss << "  }\n";
    ss << "}\n";
    return ss.str();
}
