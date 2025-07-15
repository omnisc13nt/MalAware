#include "../include/peSectionParser.h"
#include <cstring>
#include "../include/peSectionParser.h"
#include <cstring>
std::string GetSectionProtection(DWORD_PTR dCharacteristics)
{
    std::string protection = "(";
    bool bExecute = false, bRead = false;
    if (dCharacteristics & IMAGE_SCN_MEM_EXECUTE) {
        bExecute = true;
        protection += "EXECUTE";
    }
    if (dCharacteristics & IMAGE_SCN_MEM_READ) {
        bRead = true;
        if (bExecute) protection += " | ";
        protection += "READ";
    }
    if (dCharacteristics & IMAGE_SCN_MEM_WRITE) {
        if (bExecute || bRead) protection += " | ";
        protection += "WRITE";
    }
    protection += ")";
    return protection;
}
PIMAGE_SECTION_HEADER GetSections(PIMAGE_SECTION_HEADER pImageSectionHeader,
                                  int nNumberOfSections,
                                  DWORD_PTR dImportAddress)
{
    PIMAGE_SECTION_HEADER pImageImportHeader = nullptr;
    for (int i = 0; i < nNumberOfSections; ++i)
    {
        const auto pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));
        if (dImportAddress >= pCurrentSectionHeader->VirtualAddress &&
            dImportAddress < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
        {
            pImageImportHeader = pCurrentSectionHeader;
        }
    }
    return pImageImportHeader;
}
PIMAGE_SECTION_HEADER GetExportSection(PIMAGE_SECTION_HEADER pImageSectionHeader,
                                       int nNumberOfSections,
                                       DWORD_PTR dExportAddress)
{
    PIMAGE_SECTION_HEADER pImageExportHeader = nullptr;
    for (int i = 0; i < nNumberOfSections; ++i)
    {
        const auto pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));
        if (dExportAddress >= pCurrentSectionHeader->VirtualAddress &&
            dExportAddress < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
        {
            pImageExportHeader = pCurrentSectionHeader;
        }
    }
    return pImageExportHeader;
}
void DisplaySections(PIMAGE_SECTION_HEADER pImageSectionHeader, int nNumberOfSections)
{
    printf("\n[+] PE IMAGE SECTIONS\n");
    for (int i = 0; i < nNumberOfSections; ++i)
    {
        const auto pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));
        printf("\n\tSECTION : %s\n", (char*)pCurrentSectionHeader->Name);
        printf("\t\tMisc (PhysicalAddress) : 0x%X\n", (unsigned int)pCurrentSectionHeader->Misc.PhysicalAddress);
        printf("\t\tMisc (VirtualSize) : 0x%X\n", (unsigned int)pCurrentSectionHeader->Misc.VirtualSize);
        printf("\t\tVirtualAddress : 0x%X\n", (unsigned int)pCurrentSectionHeader->VirtualAddress);
        printf("\t\tSizeOfRawData : 0x%X\n", (unsigned int)pCurrentSectionHeader->SizeOfRawData);
        printf("\t\tPointerToRawData : 0x%X\n", (unsigned int)pCurrentSectionHeader->PointerToRawData);
        printf("\t\tPointerToRelocations : 0x%X\n", (unsigned int)pCurrentSectionHeader->PointerToRelocations);
        printf("\t\tPointerToLinenumbers : 0x%X\n", (unsigned int)pCurrentSectionHeader->PointerToLinenumbers);
        printf("\t\tNumberOfRelocations : 0x%X\n", (unsigned int)pCurrentSectionHeader->NumberOfRelocations);
        printf("\t\tNumberOfLinenumbers : 0x%X\n", (unsigned int)pCurrentSectionHeader->NumberOfLinenumbers);
        printf("\t\tCharacteristics : 0x%X %s\n", (unsigned int)pCurrentSectionHeader->Characteristics, GetSectionProtection(pCurrentSectionHeader->Characteristics).c_str());
    }
}
