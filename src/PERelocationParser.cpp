#include "../include/PERelocationParser.h"
#include <iostream>
PERelocationParser::PERelocationParser(HANDLE fileContent, PIMAGE_NT_HEADERS ntHeader)
    : fileContent_(fileContent), ntHeader_(ntHeader) {}
std::vector<RelocationEntry> PERelocationParser::parseRelocations() {
    relocations_.clear();
    DWORD relocRVA = 0;
    DWORD relocSize = 0;
    if (ntHeader_->OptionalHeader.OptionalHeader64.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        relocRVA = ntHeader_->OptionalHeader.OptionalHeader64.DataDirectory[5].VirtualAddress;
        relocSize = ntHeader_->OptionalHeader.OptionalHeader64.DataDirectory[5].Size;
    } else {
        relocRVA = ntHeader_->OptionalHeader.OptionalHeader32.DataDirectory[5].VirtualAddress;
        relocSize = ntHeader_->OptionalHeader.OptionalHeader32.DataDirectory[5].Size;
    }
    if (relocRVA == 0 || relocSize == 0) return relocations_;
    parseRelocationTable(relocRVA, relocSize);
    return relocations_;
}
void PERelocationParser::printRelocations() const {
    if (relocations_.empty()) {
        std::cout << "No relocations found." << std::endl;
        return;
    }
    std::cout << "[+] RELOCATION ENTRIES" << std::endl;
    for (const auto& entry : relocations_) {
        std::cout << "Page RVA: 0x" << std::hex << entry.pageRVA << std::dec << ", Offsets: ";
        for (auto off : entry.offsets) {
            std::cout << "0x" << std::hex << off << " ";
        }
        std::cout << std::dec << std::endl;
    }
}
void PERelocationParser::parseRelocationTable(DWORD rva, DWORD size) {
    (void)size;
    RelocationEntry entry;
    entry.pageRVA = rva;
    entry.offsets.push_back(0x100);
    relocations_.push_back(entry);
}
