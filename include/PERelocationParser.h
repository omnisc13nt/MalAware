#pragma once
#include "peCommon.h"
#include "outputCapture.h"
#include <vector>
#include <string>

struct RelocationEntry {
    DWORD pageRVA;
    std::vector<DWORD> offsets;
};

class PERelocationParser {
public:
    PERelocationParser(HANDLE fileContent, PIMAGE_NT_HEADERS ntHeader);
    std::vector<RelocationEntry> parseRelocations();
    void printRelocations() const;
private:
    HANDLE fileContent_;
    PIMAGE_NT_HEADERS ntHeader_;
    std::vector<RelocationEntry> relocations_;
    void parseRelocationTable(DWORD rva, DWORD size);
};
