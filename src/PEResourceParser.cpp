#include "../include/PEResourceParser.h"
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
    BYTE* base = reinterpret_cast<BYTE*>(fileContent_);
    size_t dirOffset = rva - baseRVA;
    if (dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize_)
        return;
    PIMAGE_RESOURCE_DIRECTORY resDir = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(base + dirOffset);
    int totalEntries = resDir->NumberOfNamedEntries + resDir->NumberOfIdEntries;
    size_t entriesOffset = dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
    if (entriesOffset + totalEntries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileSize_)
        return;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(base + entriesOffset);
    for (int i = 0; i < totalEntries; ++i) {
        DWORD entryType = type, entryName = name, entryLang = lang;
        if (depth == 0) {
            if (entries[i].u1.s.NameIsString)
                entryType = 0; // Named type, not handled here
            else
                entryType = entries[i].u1.Id;
        } else if (depth == 1) {
            if (entries[i].u1.s.NameIsString)
                entryName = 0; // Named resource, not handled here
            else
                entryName = entries[i].u1.Id;
        } else if (depth == 2) {
            if (entries[i].u1.s.NameIsString)
                entryLang = 0; // Named language, not handled here
            else
                entryLang = entries[i].u1.Id;
        }
        if (entries[i].u2.s2.DataIsDirectory) {
            DWORD subdirRVA = entries[i].u2.s2.OffsetToDirectory;
            if (subdirRVA == 0 || subdirRVA > fileSize_)
                continue;
            parseResourceDirectory(subdirRVA, baseRVA, depth + 1, entryType, entryName, entryLang);
        } else {
            DWORD dataEntryRVA = entries[i].u2.OffsetToData;
            size_t dataEntryOffset = dataEntryRVA - baseRVA;
            if (dataEntryRVA == 0 || dataEntryOffset + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > fileSize_)
                continue;
            PIMAGE_RESOURCE_DATA_ENTRY dataEntry = reinterpret_cast<PIMAGE_RESOURCE_DATA_ENTRY>(base + dataEntryOffset);
            if (!dataEntry || dataEntry->OffsetToData == 0 || dataEntry->Size == 0)
                continue;
            ResourceEntry entry;
            entry.type = entryType;
            entry.name = entryName;
            entry.lang = entryLang;
            entry.rva = dataEntry->OffsetToData;
            entry.size = dataEntry->Size;
            resources_.push_back(entry);
        }
    }
}
