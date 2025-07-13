#include "../include/peParser.h"
#include "../include/peHeaderParser.h"
#include "../include/peSectionParser.h"
#include "../include/peImportExport.h"

int ParsePE32(PPE_FILE_INFO pFileInfo)
{
    const auto pImageNTHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo->pNtHeader;
    const IMAGE_FILE_HEADER imageFileHeader = pImageNTHeader32->FileHeader;
    const IMAGE_OPTIONAL_HEADER32 imageOptionalHeader32 = pImageNTHeader32->OptionalHeader;

    const auto pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + imageFileHeader.SizeOfOptionalHeader);
    if (pImageSectionHeader == nullptr)
        return PE_ERROR_PARSING;

    printf("[+] PE IMAGE INFORMATION\n");
    Logger::output("[+] PE IMAGE INFORMATION");
    printf("\n[+] Architecture x86\n");
    Logger::output("\n[+] Architecture x86");

    DisplayDosHeader(pFileInfo->pDosHeader);
    DisplayNTHeader(pFileInfo);
    DisplayFileHeader(&imageFileHeader);
    DisplayOptionalHeader32(&imageOptionalHeader32);

    DisplaySections(pImageSectionHeader, imageFileHeader.NumberOfSections);

    int result = ParseImports(pFileInfo);
    if (result != PE_SUCCESS) {
        return result;
    }

    result = ParseExports(pFileInfo);
    if (result != PE_SUCCESS) {
        return result;
    }

    return PE_SUCCESS;
}

int ParsePE64(PPE_FILE_INFO pFileInfo)
{
    const auto pImageNTHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo->pNtHeader;
    const IMAGE_FILE_HEADER imageFileHeader = pImageNTHeader64->FileHeader;
    const IMAGE_OPTIONAL_HEADER64 imageOptionalHeader64 = pImageNTHeader64->OptionalHeader;

    const auto pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + imageFileHeader.SizeOfOptionalHeader);
    if (pImageSectionHeader == nullptr)
        return PE_ERROR_PARSING;

    printf("[+] PE IMAGE INFORMATION\n");
    Logger::output("[+] PE IMAGE INFORMATION");
    printf("\n[+] Architecture x64\n");
    Logger::output("\n[+] Architecture x64");

    DisplayDosHeader(pFileInfo->pDosHeader);
    DisplayNTHeader(pFileInfo);
    DisplayFileHeader(&imageFileHeader);
    DisplayOptionalHeader64(&imageOptionalHeader64);

    DisplaySections(pImageSectionHeader, imageFileHeader.NumberOfSections);

    int result = ParseImports(pFileInfo);
    if (result != PE_SUCCESS) {
        return result;
    }

    result = ParseExports(pFileInfo);
    if (result != PE_SUCCESS) {
        return result;
    }

    return PE_SUCCESS;
}

int ParsePEFile(PPE_FILE_INFO pFileInfo)
{
    if (!pFileInfo || !pFileInfo->pNtHeader) {
        return PE_ERROR_INVALID_PE;
    }

    if (pFileInfo->bIs64Bit)
    {
        return ParsePE64(pFileInfo);
    }
    else
    {
        return ParsePE32(pFileInfo);
    }
}
