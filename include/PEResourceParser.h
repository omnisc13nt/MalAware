#pragma once
#include "peCommon.h"
#include "outputCapture.h"
#include <string>
#include <vector>
#include <map>
struct ResourceEntry {
    DWORD type;
    DWORD name;
    DWORD lang;
    DWORD rva;
    DWORD size;
    std::string typeName;
    std::string nameString;
    std::vector<uint8_t> data;
};
struct VersionInfo {
    std::string fileVersion;
    std::string productVersion;
    std::string companyName;
    std::string productName;
    std::string fileDescription;
    std::string copyright;
    std::string originalFilename;
    std::string internalName;
    bool isValid;
};
struct IconInfo {
    int width;
    int height;
    int bitCount;
    std::vector<uint8_t> iconData;
    bool isValid;
};
struct StringTableInfo {
    std::map<DWORD, std::string> strings;
    int totalStrings;
    bool hasObfuscatedStrings;
};
class PEResourceParser {
public:
    PEResourceParser(HANDLE fileContent, PIMAGE_NT_HEADERS ntHeader);
    std::vector<ResourceEntry> parseResources();
    void printResources() const;
    VersionInfo extractVersionInfo();
    std::vector<IconInfo> extractIcons();
    StringTableInfo extractStringTables();
    std::vector<uint8_t> extractManifest();
    std::map<std::string, std::vector<uint8_t>> extractAllResources();
    bool hasVersionInfo() const;
    bool hasIcons() const;
    bool hasManifest() const;
    bool hasStringTables() const;
    bool hasSuspiciousResources() const;
    std::vector<std::string> analyzeResourceSecurity();
    bool detectResourceObfuscation();
    bool detectEmbeddedFiles();
private:
    HANDLE fileContent_;
    PIMAGE_NT_HEADERS ntHeader_;
    std::vector<ResourceEntry> resources_;
    DWORD fileSize_;
    void parseResourceDirectory(DWORD rva, DWORD baseRVA, int depth = 0, DWORD type = 0, DWORD name = 0, DWORD lang = 0);
    std::string getResourceTypeName(DWORD type);
    std::vector<uint8_t> getResourceData(DWORD rva, DWORD size);
    VersionInfo parseVersionResource(const std::vector<uint8_t>& data);
    std::string extractVersionString(const uint8_t* data, size_t size, const std::string& key);
    std::vector<IconInfo> parseIconResource(const std::vector<uint8_t>& data);
    IconInfo parseIconEntry(const uint8_t* data, size_t size);
    StringTableInfo parseStringTable(const std::vector<uint8_t>& data);
    bool isStringObfuscated(const std::string& str);
    bool isResourceSuspicious(const ResourceEntry& resource) const;
    bool hasHighEntropy(const std::vector<uint8_t>& data) const;
    bool containsExecutableCode(const std::vector<uint8_t>& data) const;
    DWORD rvaToFileOffset(DWORD rva);
    bool isValidRVA(DWORD rva, DWORD size = 0);
};
