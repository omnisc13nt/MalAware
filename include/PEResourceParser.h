#pragma once
#include "peCommon.h"
#include "outputCapture.h"
#include <string>
#include <vector>

struct ResourceEntry {
    DWORD type;
    DWORD name;
    DWORD lang;
    DWORD rva;
    DWORD size;
};

class PEResourceParser {
public:
    PEResourceParser(HANDLE fileContent, PIMAGE_NT_HEADERS ntHeader);
    std::vector<ResourceEntry> parseResources();
    void printResources() const;
private:
    HANDLE fileContent_;
    PIMAGE_NT_HEADERS ntHeader_;
    std::vector<ResourceEntry> resources_;
    DWORD fileSize_;
    void parseResourceDirectory(DWORD rva, DWORD baseRVA, int depth = 0, DWORD type = 0, DWORD name = 0, DWORD lang = 0);
};
