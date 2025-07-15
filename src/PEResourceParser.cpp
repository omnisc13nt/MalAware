#include "../include/PEResourceParser.h"
#include <cmath>
#include <iostream>
#include <vector>
PEResourceParser::PEResourceParser(HANDLE fileContent, PIMAGE_NT_HEADERS ntHeader)
    : fileContent_(fileContent), ntHeader_(ntHeader) {
    fileSize_ = 0;
    if (ntHeader_) {
        if (ntHeader_->OptionalHeader.OptionalHeader64.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            fileSize_ = ntHeader_->OptionalHeader.OptionalHeader64.SizeOfImage;
        } else {
            fileSize_ = ntHeader_->OptionalHeader.OptionalHeader32.SizeOfImage;
        }
    }
}
std::vector<ResourceEntry> PEResourceParser::parseResources() {
    resources_.clear();
    DWORD rsrcRVA = 0;
    DWORD rsrcSize = 0;
    if (ntHeader_->OptionalHeader.OptionalHeader64.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        rsrcRVA = ntHeader_->OptionalHeader.OptionalHeader64.DataDirectory[2].VirtualAddress;
        rsrcSize = ntHeader_->OptionalHeader.OptionalHeader64.DataDirectory[2].Size;
    } else {
        rsrcRVA = ntHeader_->OptionalHeader.OptionalHeader32.DataDirectory[2].VirtualAddress;
        rsrcSize = ntHeader_->OptionalHeader.OptionalHeader32.DataDirectory[2].Size;
    }
    if (rsrcRVA == 0 || rsrcSize == 0) return resources_;
    parseResourceDirectory(rsrcRVA, rsrcRVA, 0, 0, 0, 0);
    return resources_;
}
void PEResourceParser::printResources() const {
    if (resources_.empty()) {
        std::cout << "No resources found." << std::endl;
        return;
    }
    std::cout << "[+] RESOURCE ENTRIES" << std::endl;
    for (const auto& entry : resources_) {
        std::cout << "Type: " << entry.type << ", Name: " << entry.name << ", Lang: " << entry.lang
                  << ", RVA: 0x" << std::hex << entry.rva << ", Size: 0x" << entry.size << std::dec << std::endl;
    }
}
typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    WORD NumberOfNamedEntries;
    WORD NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset : 31;
            DWORD NameIsString : 1;
        } s;
        DWORD Name;
        WORD Id;
    } u1;
    union {
        DWORD OffsetToData;
        struct {
            DWORD OffsetToDirectory : 31;
            DWORD DataIsDirectory : 1;
        } s2;
    } u2;
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;
typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    DWORD OffsetToData;
    DWORD Size;
    DWORD CodePage;
    DWORD Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;
void PEResourceParser::parseResourceDirectory(DWORD rva, DWORD baseRVA, int depth, DWORD type, DWORD name, DWORD lang) {
    if (rva == 0 || rva > fileSize_ || !fileContent_)
        return;
    if (depth > 3) {
        std::cerr << "[WARNING] Resource directory depth exceeded limit" << std::endl;
        return;
    }
    BYTE* base = reinterpret_cast<BYTE*>(fileContent_);
    size_t dirOffset = rva - baseRVA;
    if (dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize_) {
        std::cerr << "[ERROR] Resource directory offset out of bounds" << std::endl;
        return;
    }
    PIMAGE_RESOURCE_DIRECTORY resDir = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(base + dirOffset);
    if (resDir->NumberOfNamedEntries + resDir->NumberOfIdEntries > 1000) {
        std::cerr << "[WARNING] Suspicious number of resource entries detected" << std::endl;
        return;
    }
    int totalEntries = resDir->NumberOfNamedEntries + resDir->NumberOfIdEntries;
    size_t entriesOffset = dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
    if (entriesOffset + totalEntries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileSize_) {
        std::cerr << "[ERROR] Resource entries offset out of bounds" << std::endl;
        return;
    }
    PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(base + entriesOffset);
    for (int i = 0; i < totalEntries; ++i) {
        DWORD entryType = type, entryName = name, entryLang = lang;
        if (depth == 0) {
            if (entries[i].u1.s.NameIsString)
                entryType = 0;
            else
                entryType = entries[i].u1.Id;
        } else if (depth == 1) {
            if (entries[i].u1.s.NameIsString)
                entryName = 0;
            else
                entryName = entries[i].u1.Id;
        } else if (depth == 2) {
            if (entries[i].u1.s.NameIsString)
                entryLang = 0;
            else
                entryLang = entries[i].u1.Id;
        }
        if (entries[i].u2.s2.DataIsDirectory) {
            DWORD nextRVA = baseRVA + entries[i].u2.s2.OffsetToDirectory;
            if (nextRVA > fileSize_) {
                std::cerr << "[ERROR] Invalid resource directory RVA" << std::endl;
                continue;
            }
            parseResourceDirectory(nextRVA, baseRVA, depth + 1, entryType, entryName, entryLang);
        } else {
            DWORD dataRVA = baseRVA + entries[i].u2.OffsetToData;
            if (dataRVA + sizeof(IMAGE_RESOURCE_DATA_ENTRY) <= fileSize_) {
                PIMAGE_RESOURCE_DATA_ENTRY dataEntry = reinterpret_cast<PIMAGE_RESOURCE_DATA_ENTRY>(base + dataRVA - baseRVA);
                if (dataEntry->OffsetToData < fileSize_ && dataEntry->Size < fileSize_) {
                    ResourceEntry entry;
                    entry.type = entryType;
                    entry.name = entryName;
                    entry.lang = entryLang;
                    entry.rva = dataEntry->OffsetToData;
                    entry.size = dataEntry->Size;
                    entry.data = getResourceData(entry.rva, entry.size);
                    if (entry.rva != 0 && entry.size != 0 && entry.rva < fileSize_) {
                        resources_.push_back(entry);
                    }
                }
            }
        }
    }
}
VersionInfo PEResourceParser::extractVersionInfo() {
    VersionInfo versionInfo = {};
    versionInfo.isValid = false;

    for (const auto& resource : resources_) {
        if (resource.type == 16) {
            if (resource.data.size() > sizeof(DWORD)) {
                versionInfo = parseVersionResource(resource.data);
                if (versionInfo.isValid) {
                    break;
                }
            }
        }
    }

    return versionInfo;
}

std::vector<IconInfo> PEResourceParser::extractIcons() {
    std::vector<IconInfo> icons;

    for (const auto& resource : resources_) {
        if (resource.type == 3) {
            IconInfo iconInfo = parseIconEntry(resource.data.data(), resource.data.size());
            if (iconInfo.isValid) {
                icons.push_back(iconInfo);
            }
        }
    }

    return icons;
}

StringTableInfo PEResourceParser::extractStringTables() {
    StringTableInfo stringInfo = {};
    stringInfo.totalStrings = 0;
    stringInfo.hasObfuscatedStrings = false;

    for (const auto& resource : resources_) {
        if (resource.type == 6) {
            auto parsedStrings = parseStringTable(resource.data);
            for (const auto& pair : parsedStrings.strings) {
                stringInfo.strings[pair.first] = pair.second;
                stringInfo.totalStrings++;

                if (isStringObfuscated(pair.second)) {
                    stringInfo.hasObfuscatedStrings = true;
                }
            }
        }
    }

    return stringInfo;
}

std::vector<uint8_t> PEResourceParser::extractManifest() {
    std::vector<uint8_t> manifestData;

    for (const auto& resource : resources_) {
        if (resource.type == 24) {
            manifestData = resource.data;
            break;
        }
    }

    return manifestData;
}

std::map<std::string, std::vector<uint8_t>> PEResourceParser::extractAllResources() {
    std::map<std::string, std::vector<uint8_t>> allResources;

    for (const auto& resource : resources_) {
        std::string key = getResourceTypeName(resource.type) + "_" +
                         std::to_string(resource.name) + "_" +
                         std::to_string(resource.lang);
        allResources[key] = resource.data;
    }

    return allResources;
}

bool PEResourceParser::hasVersionInfo() const {
    for (const auto& resource : resources_) {
        if (resource.type == 16) {
            return true;
        }
    }
    return false;
}

bool PEResourceParser::hasIcons() const {
    for (const auto& resource : resources_) {
        if (resource.type == 3) {
            return true;
        }
    }
    return false;
}

bool PEResourceParser::hasManifest() const {
    for (const auto& resource : resources_) {
        if (resource.type == 24) {
            return true;
        }
    }
    return false;
}

bool PEResourceParser::hasStringTables() const {
    for (const auto& resource : resources_) {
        if (resource.type == 6) {
            return true;
        }
    }
    return false;
}

bool PEResourceParser::hasSuspiciousResources() const {
    for (const auto& resource : resources_) {
        if (isResourceSuspicious(resource)) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> PEResourceParser::analyzeResourceSecurity() {
    std::vector<std::string> findings;


    for (const auto& resource : resources_) {
        if (containsExecutableCode(resource.data)) {
            findings.push_back("Executable code detected in resource " +
                             getResourceTypeName(resource.type));
        }

        if (hasHighEntropy(resource.data)) {
            findings.push_back("High entropy resource detected (possible encryption): " +
                             getResourceTypeName(resource.type));
        }


        if (resource.data.size() > 64) {
            if (resource.data[0] == 'M' && resource.data[1] == 'Z') {
                findings.push_back("Embedded PE file detected in resource " +
                                 getResourceTypeName(resource.type));
            }
        }
    }


    VersionInfo versionInfo = const_cast<PEResourceParser*>(this)->extractVersionInfo();
    if (versionInfo.isValid) {
        if (versionInfo.companyName.find("Microsoft") != std::string::npos &&
            versionInfo.productName.find("Windows") == std::string::npos) {
            findings.push_back("Potentially fake Microsoft signature in version info");
        }

        if (versionInfo.fileVersion.empty() || versionInfo.productVersion.empty()) {
            findings.push_back("Incomplete version information (possible obfuscation)");
        }
    }

    return findings;
}

bool PEResourceParser::detectResourceObfuscation() {
    int suspiciousCount = 0;

    for (const auto& resource : resources_) {
        if (hasHighEntropy(resource.data)) {
            suspiciousCount++;
        }

        if (resource.data.size() > 100000) {
            suspiciousCount++;
        }


        if (resource.type > 24 && resource.type < 256) {
            suspiciousCount++;
        }
    }

    return suspiciousCount > 2;
}

bool PEResourceParser::detectEmbeddedFiles() {
    for (const auto& resource : resources_) {
        if (containsExecutableCode(resource.data)) {
            return true;
        }


        if (resource.data.size() > 4) {
            uint32_t header = *(uint32_t*)resource.data.data();


            if (header == 0x04034b50 ||
                header == 0x474E5089 ||
                header == 0xE011CFD0 ||
                (resource.data[0] == 'M' && resource.data[1] == 'Z')) {
                return true;
            }
        }
    }

    return false;
}

VersionInfo PEResourceParser::parseVersionResource(const std::vector<uint8_t>& data) {
    VersionInfo versionInfo = {};
    versionInfo.isValid = false;

    if (data.size() < 40) {
        return versionInfo;
    }

    const uint8_t* dataPtr = data.data();


    std::string dataStr(reinterpret_cast<const char*>(dataPtr), data.size());

    versionInfo.fileVersion = extractVersionString(dataPtr, data.size(), "FileVersion");
    versionInfo.productVersion = extractVersionString(dataPtr, data.size(), "ProductVersion");
    versionInfo.companyName = extractVersionString(dataPtr, data.size(), "CompanyName");
    versionInfo.productName = extractVersionString(dataPtr, data.size(), "ProductName");
    versionInfo.fileDescription = extractVersionString(dataPtr, data.size(), "FileDescription");
    versionInfo.copyright = extractVersionString(dataPtr, data.size(), "LegalCopyright");
    versionInfo.originalFilename = extractVersionString(dataPtr, data.size(), "OriginalFilename");
    versionInfo.internalName = extractVersionString(dataPtr, data.size(), "InternalName");

    versionInfo.isValid = !versionInfo.fileVersion.empty() || !versionInfo.productVersion.empty();

    return versionInfo;
}

std::string PEResourceParser::extractVersionString(const uint8_t* data, size_t size, const std::string& key) {
    std::string result;


    std::wstring wkey(key.begin(), key.end());
    std::vector<uint8_t> searchPattern;

    for (wchar_t c : wkey) {
        searchPattern.push_back(c & 0xFF);
        searchPattern.push_back((c >> 8) & 0xFF);
    }


    for (size_t i = 0; i < size - searchPattern.size() - 20; i++) {
        bool found = true;
        for (size_t j = 0; j < searchPattern.size(); j++) {
            if (data[i + j] != searchPattern[j]) {
                found = false;
                break;
            }
        }

        if (found) {

            size_t valueStart = i + searchPattern.size() + 2;


            std::wstring wvalue;
            for (size_t k = valueStart; k < size - 1 && k < valueStart + 256; k += 2) {
                wchar_t wc = data[k] | (data[k + 1] << 8);
                if (wc == 0) break;
                if (wc < 256) wvalue += wc;
            }

            result.assign(wvalue.begin(), wvalue.end());
            break;
        }
    }

    return result;
}

std::vector<IconInfo> PEResourceParser::parseIconResource(const std::vector<uint8_t>& data) {
    std::vector<IconInfo> icons;

    if (data.size() < 6) {
        return icons;
    }


    const uint8_t* dataPtr = data.data();
    uint16_t iconCount = *(uint16_t*)(dataPtr + 4);

    if (iconCount > 100) {
        return icons;
    }

    for (uint16_t i = 0; i < iconCount && (6 + i * 16) < data.size(); i++) {
        IconInfo iconInfo = parseIconEntry(dataPtr + 6 + i * 16, 16);
        if (iconInfo.isValid) {
            icons.push_back(iconInfo);
        }
    }

    return icons;
}

IconInfo PEResourceParser::parseIconEntry(const uint8_t* data, size_t size) {
    IconInfo iconInfo = {};
    iconInfo.isValid = false;

    if (size < 16) {
        return iconInfo;
    }

    iconInfo.width = data[0] == 0 ? 256 : data[0];
    iconInfo.height = data[1] == 0 ? 256 : data[1];
    iconInfo.bitCount = *(uint16_t*)(data + 6);

    uint32_t imageSize = *(uint32_t*)(data + 8);
    if (imageSize > 0 && imageSize < 1024 * 1024) {
        iconInfo.iconData.resize(imageSize);
        if (size >= 16 + imageSize) {
            std::memcpy(iconInfo.iconData.data(), data + 16, imageSize);
        }
    }

    iconInfo.isValid = (iconInfo.width > 0 && iconInfo.height > 0);

    return iconInfo;
}

StringTableInfo PEResourceParser::parseStringTable(const std::vector<uint8_t>& data) {
    StringTableInfo stringInfo = {};
    stringInfo.totalStrings = 0;
    stringInfo.hasObfuscatedStrings = false;


    const uint8_t* dataPtr = data.data();
    size_t offset = 0;
    DWORD stringId = 0;

    while (offset < data.size() - 4) {

        std::wstring wstr;
        size_t strStart = offset;

        while (offset < data.size() - 1) {
            wchar_t wc = dataPtr[offset] | (dataPtr[offset + 1] << 8);
            offset += 2;

            if (wc == 0) break;
            if (wc < 256 && wc >= 32) {
                wstr += wc;
            }
        }

        if (wstr.length() > 3) {
            std::string str(wstr.begin(), wstr.end());
            stringInfo.strings[stringId++] = str;
            stringInfo.totalStrings++;

            if (isStringObfuscated(str)) {
                stringInfo.hasObfuscatedStrings = true;
            }
        }

        if (offset == strStart) offset += 2;
    }

    return stringInfo;
}

bool PEResourceParser::isStringObfuscated(const std::string& str) {
    if (str.length() < 8) return false;


    int base64Count = 0;
    for (char c : str) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            base64Count++;
        }
    }

    if (base64Count > str.length() * 0.8) return true;


    if (str.find("AAAA") != std::string::npos ||
        str.find("0000") != std::string::npos ||
        str.find("xxxx") != std::string::npos) {
        return true;
    }

    return false;
}

bool PEResourceParser::isResourceSuspicious(const ResourceEntry& resource) const {

    if (resource.size > 10 * 1024 * 1024) return true;


    if (hasHighEntropy(resource.data)) return true;


    if (resource.type != 3 && resource.type != 16 && containsExecutableCode(resource.data)) {
        return true;
    }

    return false;
}

bool PEResourceParser::hasHighEntropy(const std::vector<uint8_t>& data) const {
    if (data.size() < 256) return false;

    std::vector<int> frequency(256, 0);
    for (uint8_t byte : data) {
        frequency[byte]++;
    }

    double entropy = 0.0;
    for (int freq : frequency) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / data.size();
            entropy -= probability * log2(probability);
        }
    }

    return entropy > 7.5;
}

bool PEResourceParser::containsExecutableCode(const std::vector<uint8_t>& data) const {
    if (data.size() < 64) return false;


    if (data[0] == 'M' && data[1] == 'Z') return true;


    const std::vector<std::vector<uint8_t>> patterns = {
        {0x55, 0x8B, 0xEC},
        {0x48, 0x83, 0xEC},
        {0x40, 0x53, 0x48},
        {0xE8, 0x00, 0x00, 0x00, 0x00},
    };

    for (const auto& pattern : patterns) {
        for (size_t i = 0; i <= data.size() - pattern.size(); i++) {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); j++) {
                if (pattern[j] != 0x00 && data[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return true;
        }
    }

    return false;
}


std::string PEResourceParser::getResourceTypeName(DWORD type) {
    switch (type) {
        case 1: return "RT_CURSOR";
        case 2: return "RT_BITMAP";
        case 3: return "RT_ICON";
        case 4: return "RT_MENU";
        case 5: return "RT_DIALOG";
        case 6: return "RT_STRING";
        case 7: return "RT_FONTDIR";
        case 8: return "RT_FONT";
        case 9: return "RT_ACCELERATOR";
        case 10: return "RT_RCDATA";
        case 11: return "RT_MESSAGETABLE";
        case 12: return "RT_GROUP_CURSOR";
        case 14: return "RT_GROUP_ICON";
        case 16: return "RT_VERSION";
        case 17: return "RT_DLGINCLUDE";
        case 19: return "RT_PLUGPLAY";
        case 20: return "RT_VXD";
        case 21: return "RT_ANICURSOR";
        case 22: return "RT_ANIICON";
        case 23: return "RT_HTML";
        case 24: return "RT_MANIFEST";
        default: return "RT_UNKNOWN_" + std::to_string(type);
    }
}

DWORD PEResourceParser::rvaToFileOffset(DWORD rva) {

    return rva;
}

bool PEResourceParser::isValidRVA(DWORD rva, DWORD size) {
    return (rva != 0 && rva < fileSize_ && (rva + size) <= fileSize_);
}

std::vector<uint8_t> PEResourceParser::getResourceData(DWORD rva, DWORD size) {
    std::vector<uint8_t> data;

    if (!isValidRVA(rva, size) || !fileContent_) {
        return data;
    }


    DWORD fileOffset = rvaToFileOffset(rva);

    if (fileOffset + size <= fileSize_) {
        data.resize(size);
        BYTE* fileData = reinterpret_cast<BYTE*>(fileContent_);
        std::memcpy(data.data(), fileData + fileOffset, size);
    }

    return data;
}
