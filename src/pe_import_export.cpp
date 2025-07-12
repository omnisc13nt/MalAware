#include "../include/pe_import_export.h"
#include "../include/pe_section_parser.h"

void GetImports32(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor, 
                  DWORD_PTR dRawOffset, 
                  PIMAGE_SECTION_HEADER pImageImportSection)
{
    printf("\n[+] IMPORTED DLL\n");

    while (pImageImportDescriptor->Name != 0)
    {
        printf("\n\tDLL NAME : %s\n", (char*)(dRawOffset + (pImageImportDescriptor->Name - pImageImportSection->VirtualAddress)));
        printf("\tCharacteristics : 0x%X\n", (unsigned int)(dRawOffset + (pImageImportDescriptor->Characteristics - pImageImportSection->VirtualAddress)));
        printf("\tOriginalFirstThunk : 0x%X\n", (unsigned int)(dRawOffset + (pImageImportDescriptor->OriginalFirstThunk - pImageImportSection->VirtualAddress)));
        printf("\tTimeDateStamp : 0x%X\n", (unsigned int)(dRawOffset + (pImageImportDescriptor->TimeDateStamp - pImageImportSection->VirtualAddress)));
        printf("\tForwarderChain : 0x%X\n", (unsigned int)(dRawOffset + (pImageImportDescriptor->ForwarderChain - pImageImportSection->VirtualAddress)));
        printf("\tFirstThunk : 0x%X\n", (unsigned int)(dRawOffset + (pImageImportDescriptor->FirstThunk - pImageImportSection->VirtualAddress)));

        if (pImageImportDescriptor->OriginalFirstThunk == 0)
        {
            ++pImageImportDescriptor;
            continue;
        }

        auto pOriginalFirstThunk = (PIMAGE_THUNK_DATA32)(dRawOffset + (pImageImportDescriptor->OriginalFirstThunk - pImageImportSection->VirtualAddress));

        printf("\n\tImported Functions : \n\n");

        while (pOriginalFirstThunk->u1.AddressOfData != 0)
        {
            if (pOriginalFirstThunk->u1.AddressOfData >= IMAGE_ORDINAL_FLAG32)
            {
                ++pOriginalFirstThunk;
                continue;
            }

            const auto pImageImportByName = (PIMAGE_IMPORT_BY_NAME)(dRawOffset + (pOriginalFirstThunk->u1.AddressOfData - pImageImportSection->VirtualAddress));
            if (pImageImportByName == nullptr)
            {
                ++pOriginalFirstThunk;
                continue;
            }

            if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                printf("\t\t0x%X (Ordinal) : %s\n", (unsigned int)pOriginalFirstThunk->u1.AddressOfData, (char*)(dRawOffset + (pImageImportByName->Name - pImageImportSection->VirtualAddress)));
            else
                printf("\t\t%s\n", (char*)(dRawOffset + (pImageImportByName->Name - pImageImportSection->VirtualAddress)));

            ++pOriginalFirstThunk;
        }

        ++pImageImportDescriptor;
    }
}

void GetImports64(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor, 
                  DWORD_PTR dRawOffset, 
                  PIMAGE_SECTION_HEADER pImageImportSection)
{
    printf("\n[+] IMPORTED DLL\n");

    while (pImageImportDescriptor->Name != 0)
    {
        printf("\n\tDLL NAME : %s\n", (char*)(dRawOffset + (pImageImportDescriptor->Name - pImageImportSection->VirtualAddress)));
        printf("\tCharacteristics : 0x%X\n", (unsigned int)(dRawOffset + (pImageImportDescriptor->Characteristics - pImageImportSection->VirtualAddress)));
        printf("\tOriginalFirstThunk : 0x%X\n", (unsigned int)(dRawOffset + (pImageImportDescriptor->OriginalFirstThunk - pImageImportSection->VirtualAddress)));
        printf("\tTimeDateStamp : 0x%X\n", (unsigned int)(dRawOffset + (pImageImportDescriptor->TimeDateStamp - pImageImportSection->VirtualAddress)));
        printf("\tForwarderChain : 0x%X\n", (unsigned int)(dRawOffset + (pImageImportDescriptor->ForwarderChain - pImageImportSection->VirtualAddress)));
        printf("\tFirstThunk : 0x%X\n", (unsigned int)(dRawOffset + (pImageImportDescriptor->FirstThunk - pImageImportSection->VirtualAddress)));

        if (pImageImportDescriptor->OriginalFirstThunk == 0)
        {
            ++pImageImportDescriptor;
            continue;
        }

        auto pOriginalFirstThunk = (PIMAGE_THUNK_DATA64)(dRawOffset + (pImageImportDescriptor->OriginalFirstThunk - pImageImportSection->VirtualAddress));

        printf("\n\tImported Functions : \n\n");

        while (pOriginalFirstThunk->u1.AddressOfData != 0)
        {
            if (pOriginalFirstThunk->u1.AddressOfData >= IMAGE_ORDINAL_FLAG64)
            {
                ++pOriginalFirstThunk;
                continue;
            }

            const auto pImageImportByName = (PIMAGE_IMPORT_BY_NAME)(dRawOffset + (pOriginalFirstThunk->u1.AddressOfData - pImageImportSection->VirtualAddress));
            if (pImageImportByName == nullptr)
            {
                ++pOriginalFirstThunk;
                continue;
            }

            if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                printf("\t\t0x%llX (Ordinal) : %s\n", (unsigned long long)pOriginalFirstThunk->u1.AddressOfData, (char*)(dRawOffset + (pImageImportByName->Name - pImageImportSection->VirtualAddress)));
            else
                printf("\t\t%s\n", (char*)(dRawOffset + (pImageImportByName->Name - pImageImportSection->VirtualAddress)));

            ++pOriginalFirstThunk;
        }

        ++pImageImportDescriptor;
    }
}

void GetExports(PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, 
                DWORD_PTR dRawOffset, 
                PIMAGE_SECTION_HEADER pImageExportSection)
{
    printf("\n[+] EXPORTED FUNCTIONS\n\n");

    const DWORD_PTR dNumberOfNames = pImageExportDirectory->NumberOfNames;
    const auto pArrayOfFunctionsNames = (DWORD*)(dRawOffset + (pImageExportDirectory->AddressOfNames - pImageExportSection->VirtualAddress));
    
    for (int i = 0; i < (int)dNumberOfNames; ++i)
    {
        printf("\t%s\n", (char*)(dRawOffset + (pArrayOfFunctionsNames[i] - pImageExportSection->VirtualAddress)));
    }
}

int ParseImports(PPE_FILE_INFO pFileInfo)
{
    if (!pFileInfo || !pFileInfo->pNtHeader) {
        return PE_ERROR_INVALID_PE;
    }

    PIMAGE_DATA_DIRECTORY pDataDirectory;
    PIMAGE_SECTION_HEADER pSectionHeader;
    DWORD_PTR dImportAddress;

    if (pFileInfo->bIs64Bit)
    {
        const auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo->pNtHeader;
        pDataDirectory = pNtHeader64->OptionalHeader.DataDirectory;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader64->FileHeader.SizeOfOptionalHeader);
        dImportAddress = pDataDirectory[1].VirtualAddress;
    }
    else
    {
        const auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo->pNtHeader;
        pDataDirectory = pNtHeader32->OptionalHeader.DataDirectory;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader32->FileHeader.SizeOfOptionalHeader);
        dImportAddress = pDataDirectory[1].VirtualAddress;
    }

    if (dImportAddress == 0) {
        printf("\n[-] No import table found!\n");
        return PE_SUCCESS;
    }

    const PIMAGE_SECTION_HEADER pImageImportSection = GetSections(pSectionHeader, 
                                                                  pFileInfo->pNtHeader->FileHeader.NumberOfSections, 
                                                                  dImportAddress);
    if (pImageImportSection == nullptr)
    {
        printf("\n[-] An error when trying to retrieve PE imports!\n");
        return PE_ERROR_PARSING;
    }

    DWORD_PTR dRawOffset = (DWORD_PTR)pFileInfo->pDosHeader + pImageImportSection->PointerToRawData;
    const auto pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dRawOffset + (dImportAddress - pImageImportSection->VirtualAddress));
    if (pImageImportDescriptor == nullptr)
    {
        printf("\n[-] An error occurred when trying to retrieve PE imports descriptor!\n");
        return PE_ERROR_PARSING;
    }

    if (pFileInfo->bIs64Bit)
    {
        GetImports64(pImageImportDescriptor, dRawOffset, pImageImportSection);
    }
    else
    {
        GetImports32(pImageImportDescriptor, dRawOffset, pImageImportSection);
    }

    return PE_SUCCESS;
}

int ParseExports(PPE_FILE_INFO pFileInfo)
{
    if (!pFileInfo || !pFileInfo->pNtHeader) {
        return PE_ERROR_INVALID_PE;
    }

    PIMAGE_DATA_DIRECTORY pDataDirectory;
    PIMAGE_SECTION_HEADER pSectionHeader;
    DWORD_PTR dExportAddress;

    if (pFileInfo->bIs64Bit)
    {
        const auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo->pNtHeader;
        pDataDirectory = pNtHeader64->OptionalHeader.DataDirectory;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader64->FileHeader.SizeOfOptionalHeader);
        dExportAddress = pDataDirectory[0].VirtualAddress;
    }
    else
    {
        const auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo->pNtHeader;
        pDataDirectory = pNtHeader32->OptionalHeader.DataDirectory;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader32->FileHeader.SizeOfOptionalHeader);
        dExportAddress = pDataDirectory[0].VirtualAddress;
    }

    if (dExportAddress == 0) {
        printf("\n[-] No export table found!\n");
        return PE_SUCCESS;
    }

    const PIMAGE_SECTION_HEADER pImageExportSection = GetExportSection(pSectionHeader, 
                                                                       pFileInfo->pNtHeader->FileHeader.NumberOfSections, 
                                                                       dExportAddress);
    if (pImageExportSection == nullptr)
    {
        printf("\n[-] An error when trying to retrieve PE exports!\n");
        return PE_ERROR_PARSING;
    }

    DWORD_PTR dRawOffset = (DWORD_PTR)pFileInfo->pDosHeader + pImageExportSection->PointerToRawData;
    const auto pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dRawOffset + (dExportAddress - pImageExportSection->VirtualAddress));
    
    GetExports(pImageExportDirectory, dRawOffset, pImageExportSection);

    return PE_SUCCESS;
}
