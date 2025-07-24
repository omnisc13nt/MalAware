#include <cstring>
#include <cctype>
#include "../include/peSectionParser.h"
DWORD_PTR RvaToFileOffset(DWORD_PTR rva, PIMAGE_SECTION_HEADER pSectionHeader, int nNumberOfSections)
{
    for (int i = 0; i < nNumberOfSections; ++i)
    {
        const auto pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));
        if (rva >= pCurrentSectionHeader->VirtualAddress &&
            rva < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
        {
            DWORD_PTR offset = (DWORD_PTR)pCurrentSectionHeader->PointerToRawData + (rva - pCurrentSectionHeader->VirtualAddress);
            if (offset >= pCurrentSectionHeader->PointerToRawData &&
                offset < pCurrentSectionHeader->PointerToRawData + pCurrentSectionHeader->SizeOfRawData)
                return offset;
            else
                return 0;
        }
    }
    return 0;
}
#include "../include/peImportExport.h"
#include "../include/peSectionParser.h"
void GetImports32(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor,
                  DWORD_PTR dRawOffset,
                  PIMAGE_SECTION_HEADER pImageImportSection)
{
    LOG("\n[+] IMPORTED DLL\n");
    LOGF_DEBUG("[DEBUG] Starting 32-bit import parsing\n");
    LOGF_DEBUG("[DEBUG] pImageImportDescriptor: %p\n", (void*)pImageImportDescriptor);
    LOGF_DEBUG("[DEBUG] pImageImportSection: %p\n", (void*)pImageImportSection);
    if (!pImageImportDescriptor) {
        LOG("[-] ERROR: pImageImportDescriptor is null\n");
        return;
    }
    if (!pImageImportSection) {
        LOG("[-] ERROR: pImageImportSection is null\n");
        return;
    }
    extern int g_NumberOfSections;
    extern PIMAGE_SECTION_HEADER g_SectionHeader;
    extern int g_CorruptedImports;
    extern int g_InvalidDLLNames;
    g_CorruptedImports = 0;
    g_InvalidDLLNames = 0;
    LOGF_DEBUG("[DEBUG] g_NumberOfSections: %d\n", g_NumberOfSections);
    LOGF_DEBUG("[DEBUG] g_SectionHeader: %p\n", (void*)g_SectionHeader);
    if (!g_SectionHeader) {
        LOG("[-] ERROR: g_SectionHeader is null\n");
        return;
    }


    DWORD_PTR fileBase = dRawOffset - pImageImportSection->PointerToRawData;
    LOGF_DEBUG("[DEBUG] fileBase calculated as: %p\n", (void*)fileBase);
    int dllCount = 0;
    int maxDlls = 100;
    LOGF_DEBUG("[DEBUG] Starting import descriptor loop\n");
    while (pImageImportDescriptor->Name != 0 && maxDlls-- > 0)
    {
        LOGF_DEBUG("[DEBUG] Processing DLL #%d, Name RVA: 0x%X\n", dllCount + 1, (unsigned int)pImageImportDescriptor->Name);
        DWORD_PTR dllNameOffset = RvaToFileOffset(pImageImportDescriptor->Name, g_SectionHeader, g_NumberOfSections);
        LOGF_DEBUG("[DEBUG] DLL name offset: 0x%lX\n", (unsigned long)dllNameOffset);

        const char* dllName = "[Invalid]";
        if (dllNameOffset > 0)
        {
            const char* dllNamePtr = (const char*)(fileBase + dllNameOffset);
            LOGF_DEBUG("[DEBUG] DLL name pointer: %p\n", (void*)dllNamePtr);


            if (dllNamePtr && isValidString(dllNamePtr, 256)) {
                dllName = dllNamePtr;
                LOGF_DEBUG("[DEBUG] DLL name validated successfully: %s\n", dllName);
            } else {
                LOGF_DEBUG("[DEBUG] DLL name validation failed\n");
                g_InvalidDLLNames++;
            }
        } else {
            g_InvalidDLLNames++;
        }
        LOGF("\n\tDLL NAME : %s\n", dllName);
        LOGF("\tCharacteristics : 0x%X\n", (unsigned int)pImageImportDescriptor->Characteristics);
        LOGF("\tOriginalFirstThunk : 0x%llX\n", (unsigned long long)pImageImportDescriptor->OriginalFirstThunk);
        LOGF("\tTimeDateStamp : 0x%X\n", (unsigned int)pImageImportDescriptor->TimeDateStamp);
        LOGF("\tForwarderChain : 0x%X\n", (unsigned int)pImageImportDescriptor->ForwarderChain);
        LOGF("\tFirstThunk : 0x%llX\n", (unsigned long long)pImageImportDescriptor->FirstThunk);
        if (pImageImportDescriptor->OriginalFirstThunk == 0)
        {
            LOGF("\t[!] No OriginalFirstThunk, skipping imported functions.\n");
            ++pImageImportDescriptor;
            ++dllCount;
            continue;
        }
        DWORD_PTR thunkOffset = RvaToFileOffset(pImageImportDescriptor->OriginalFirstThunk, g_SectionHeader, g_NumberOfSections);
        LOGF_DEBUG("[DEBUG] Thunk offset: 0x%lX\n", (unsigned long)thunkOffset);
        if (thunkOffset == 0) {
            LOGF("\t[!] Invalid thunk offset, attempting FirstThunk fallback.\n");
            thunkOffset = RvaToFileOffset(pImageImportDescriptor->FirstThunk, g_SectionHeader, g_NumberOfSections);
            if (thunkOffset == 0) {
                LOGF("\t[!] Both OriginalFirstThunk and FirstThunk invalid, skipping.\n");
                ++pImageImportDescriptor;
                ++dllCount;
                continue;
            }
        }
        auto pOriginalFirstThunk = (PIMAGE_THUNK_DATA32)(fileBase + thunkOffset);
        LOGF("\n\tImported Functions : \n\n");
        int funcCount = 0;
        int invalidCount = 0;
        int maxFuncs = 1000;
        bool possibleObfuscation = false;
        LOGF_DEBUG("[DEBUG] Starting function enumeration loop\n");
        while (pOriginalFirstThunk && pOriginalFirstThunk->u1.AddressOfData != 0 && maxFuncs-- > 0)
        {
            LOGF_DEBUG("[DEBUG] Processing function, AddressOfData: 0x%X\n", (unsigned int)pOriginalFirstThunk->u1.AddressOfData);
            if (pOriginalFirstThunk->u1.AddressOfData == 0xFFFFFFFF ||
                pOriginalFirstThunk->u1.AddressOfData < 0x1000) {
                LOGF("\t\t[Corrupted Entry - Address: 0x%X]\n", (unsigned int)pOriginalFirstThunk->u1.AddressOfData);
                invalidCount++;
                g_CorruptedImports++;
                possibleObfuscation = true;
                ++pOriginalFirstThunk;
                continue;
            }
            if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
            {
                WORD ordinal = (WORD)(pOriginalFirstThunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
                LOGF("\t\tOrdinal #%d\n", ordinal);
                ++funcCount;
            }
            else
            {
                DWORD_PTR nameOffset = RvaToFileOffset(pOriginalFirstThunk->u1.AddressOfData, g_SectionHeader, g_NumberOfSections);
                LOGF_DEBUG("[DEBUG] Function name offset: 0x%lX\n", (unsigned long)nameOffset);
                const char* funcName = "[Invalid]";
                bool isObfuscated = false;
                if (nameOffset > 0)
                {
                    const auto pImageImportByName = (PIMAGE_IMPORT_BY_NAME)(fileBase + nameOffset);
                    LOGF_DEBUG("[DEBUG] Function name pointer: %p\n", (void*)pImageImportByName);
                    if (pImageImportByName)
                    {
                        const char* rawName = (const char*)pImageImportByName->Name;
                        if (isValidString(rawName, 256))
                        {
                            funcName = rawName;
                            LOGF_DEBUG("[DEBUG] Function name: %s\n", funcName);
                            size_t nameLen = strnlen(rawName, 256);
                            if (isLikelyObfuscated(rawName, nameLen)) {
                                isObfuscated = true;
                                possibleObfuscation = true;
                            }
                        }
                        else
                        {
                            invalidCount++;
                            g_CorruptedImports++;
                            possibleObfuscation = true;
                            WORD hint = pImageImportByName->Hint;
                            if (hint < 0xFFFF && hint > 0) {
                                LOGF("\t\t[Corrupted - Hint: %d, Invalid Name]\n", hint);
                            } else {
                                LOGF("\t\t[Invalid]\n");
                            }
                            ++funcCount;
                            ++pOriginalFirstThunk;
                            continue;
                        }
                    }
                }
                if (isObfuscated) {
                    LOGF("\t\t%s [OBFUSCATED]\n", funcName);
                } else {
                    LOGF("\t\t%s\n", funcName);
                }
                ++funcCount;
            }
            ++pOriginalFirstThunk;
        }
        if (funcCount == 0) {
            LOGF("\t\t[!] No imported functions found for this DLL.\n");
        } else {
            LOGF("\t\t[+] Found %d imported functions", funcCount);
            if (invalidCount > 0) {
                LOGF(" (%d invalid/corrupted)", invalidCount);
            }
            if (possibleObfuscation) {
                LOGF(" [POSSIBLE OBFUSCATION DETECTED]");
            }
            LOGF(".\n");
        }
        if (possibleObfuscation) {
            LOGF("\t\t[MALWARE ANALYSIS] This DLL shows signs of import obfuscation,\n");
            LOGF("\t\t                  commonly used by malware to evade analysis.\n");
        }
        if (strcmp(dllName, "[Invalid]") != 0) {
            size_t nameLen = strlen(dllName);
            if (nameLen < 3 ||
                (nameLen < 6 && strstr(dllName, ".dll") == nullptr) ||
                isLikelyObfuscated(dllName, nameLen)) {
                LOGF("\t\t[MALWARE ANALYSIS] Suspicious DLL name detected.\n");
            }
        }
        ++pImageImportDescriptor;
        ++dllCount;
        LOGF_DEBUG("[DEBUG] Finished processing DLL #%d\n", dllCount);
    }
    LOGF("\n[+] Total imported DLLs: %d\n", dllCount);
    LOGF_DEBUG("[DEBUG] GetImports32 completed successfully\n");
}
void GetImports64(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor,
                  DWORD_PTR dRawOffset,
                  PIMAGE_SECTION_HEADER pImageImportSection)
{
    LOGF("\n[+] IMPORTED DLL\n");
    LOGF_DEBUG("[DEBUG] Starting 64-bit import parsing\n");
    LOGF_DEBUG("[DEBUG] pImageImportDescriptor: %p\n", (void*)pImageImportDescriptor);
    LOGF_DEBUG("[DEBUG] pImageImportSection: %p\n", (void*)pImageImportSection);
    LOGF_DEBUG("[DEBUG] dRawOffset: %p\n", (void*)dRawOffset);
    if (!pImageImportDescriptor) {
        LOGF("[-] ERROR: pImageImportDescriptor is null\n");
        return;
    }
    if (!pImageImportSection) {
        LOGF("[-] ERROR: pImageImportSection is null\n");
        return;
    }
    extern int g_NumberOfSections;
    extern PIMAGE_SECTION_HEADER g_SectionHeader;
    LOGF_DEBUG("[DEBUG] g_NumberOfSections: %d\n", g_NumberOfSections);
    LOGF_DEBUG("[DEBUG] g_SectionHeader: %p\n", (void*)g_SectionHeader);
    if (!g_SectionHeader) {
        LOGF("[-] ERROR: g_SectionHeader is null\n");
        return;
    }


    DWORD_PTR fileBase = dRawOffset - pImageImportSection->PointerToRawData;
    LOGF_DEBUG("[DEBUG] fileBase calculated as: %p\n", (void*)fileBase);
    int dllCount = 0;
    int maxDlls = 100;
    LOGF_DEBUG("[DEBUG] Starting while loop, checking pImageImportDescriptor->Name: 0x%X", (unsigned int)pImageImportDescriptor->Name);
    while (pImageImportDescriptor->Name != 0 && maxDlls-- > 0)
    {
        LOGF_DEBUG("[DEBUG] Processing DLL at iteration %d", dllCount);
        DWORD_PTR dllNameOffset = RvaToFileOffset(pImageImportDescriptor->Name, g_SectionHeader, g_NumberOfSections);
        LOGF_DEBUG("[DEBUG] DLL name offset: 0x%llX", (unsigned long long)dllNameOffset);

        const char* dllName = "[Invalid]";
        if (dllNameOffset > 0)
        {
            const char* dllNamePtr = (const char*)(fileBase + dllNameOffset);
            LOGF_DEBUG("[DEBUG] DLL name pointer: %p", dllNamePtr);

            if (dllNamePtr && isValidString(dllNamePtr, 256)) {
                dllName = dllNamePtr;
                LOGF_DEBUG("[DEBUG] Successfully read DLL name: %s", dllName);
            } else {
                LOGF_DEBUG("[DEBUG] DLL name validation failed, using [Invalid]");
            }
        } else {
            LOGF_DEBUG("[DEBUG] dllNameOffset is 0, using [Invalid]");
        }
        printf("\n\tDLL NAME : %s\n", dllName);
        printf("\tCharacteristics : 0x%X\n", (unsigned int)pImageImportDescriptor->Characteristics);
        printf("\tOriginalFirstThunk : 0x%llX\n", (unsigned long long)pImageImportDescriptor->OriginalFirstThunk);
        printf("\tTimeDateStamp : 0x%X\n", (unsigned int)pImageImportDescriptor->TimeDateStamp);
        printf("\tForwarderChain : 0x%X\n", (unsigned int)pImageImportDescriptor->ForwarderChain);
        printf("\tFirstThunk : 0x%llX\n", (unsigned long long)pImageImportDescriptor->FirstThunk);
        if (pImageImportDescriptor->OriginalFirstThunk == 0)
        {
            printf("\t[!] No OriginalFirstThunk, skipping imported functions.\n");
            ++pImageImportDescriptor;
            ++dllCount;
            continue;
        }
        DWORD_PTR thunkOffset = RvaToFileOffset(pImageImportDescriptor->OriginalFirstThunk, g_SectionHeader, g_NumberOfSections);
        if (thunkOffset == 0) {
            printf("\t[!] Invalid thunk offset, skipping imported functions.\n");
            ++pImageImportDescriptor;
            ++dllCount;
            continue;
        }
        auto pOriginalFirstThunk = (PIMAGE_THUNK_DATA64)(fileBase + thunkOffset);
        printf("\n\tImported Functions : \n\n");
        int funcCount = 0;
        int maxFuncs = 1000;
        while (pOriginalFirstThunk && pOriginalFirstThunk->u1.AddressOfData != 0 && maxFuncs-- > 0)
        {
            if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
            {
                printf("\t\tOrdinal #%llu\n", (unsigned long long)(pOriginalFirstThunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG64));
                ++funcCount;
            }
            else
            {
                DWORD_PTR nameOffset = RvaToFileOffset(pOriginalFirstThunk->u1.AddressOfData, g_SectionHeader, g_NumberOfSections);
                const char* funcName = "[Invalid]";
                if (nameOffset > 0)
                {
                    const auto pImageImportByName = (PIMAGE_IMPORT_BY_NAME)(fileBase + nameOffset);
                    if (pImageImportByName && isValidString((const char*)pImageImportByName->Name, 256))
                    {
                        funcName = (const char*)pImageImportByName->Name;
                    }
                }
                printf("\t\t%s\n", funcName);
                ++funcCount;
            }
            ++pOriginalFirstThunk;
        }
        if (funcCount == 0)
            printf("\t\t[!] No imported functions found for this DLL.\n");
        else
            printf("\t\t[+] Found %d imported functions.\n", funcCount);
        ++pImageImportDescriptor;
        ++dllCount;
    }
    printf("\n[+] Total imported DLLs: %d\n", dllCount);
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
    LOGF_DEBUG("[DEBUG] ParseImports called\n");
    if (!pFileInfo || !pFileInfo->ntHeader) {
        LOG("[-] ERROR: Invalid pFileInfo or pNtHeader in ParseImports\n");
        return PE_ERROR_INVALID_PE;
    }
    LOGF_DEBUG("[DEBUG] pFileInfo: %p, pNtHeader: %p, bIs64Bit: %s\n",
         (void*)pFileInfo, (void*)pFileInfo->ntHeader, pFileInfo->is64Bit ? "true" : "false");
    PIMAGE_DATA_DIRECTORY pDataDirectory;
    PIMAGE_SECTION_HEADER pSectionHeader;
    DWORD_PTR dImportAddress;
    if (pFileInfo->is64Bit)
    {
        LOGF_DEBUG("[DEBUG] Processing 64-bit PE file\n");
        const auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo->ntHeader;
        pDataDirectory = pNtHeader64->OptionalHeader.DataDirectory;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader64->FileHeader.SizeOfOptionalHeader);
        dImportAddress = pDataDirectory[1].VirtualAddress;
        LOGF_DEBUG("[DEBUG] 64-bit import address: 0x%lX\n", (unsigned long)dImportAddress);
    }
    else
    {
        LOGF_DEBUG("[DEBUG] Processing 32-bit PE file\n");
        const auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo->ntHeader;
        pDataDirectory = pNtHeader32->OptionalHeader.DataDirectory;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader32->FileHeader.SizeOfOptionalHeader);
        dImportAddress = pDataDirectory[1].VirtualAddress;
        LOGF_DEBUG("[DEBUG] 32-bit import address: 0x%lX\n", (unsigned long)dImportAddress);
    }
    if (dImportAddress == 0) {
        LOG("\n[-] No import table found!\n");
        return PE_SUCCESS;
    }
    LOGF_DEBUG("[DEBUG] Looking for import section containing RVA 0x%lX\n", (unsigned long)dImportAddress);
    const PIMAGE_SECTION_HEADER pImageImportSection = GetSections(pSectionHeader,
                                                                  pFileInfo->ntHeader->FileHeader.NumberOfSections,
                                                                  dImportAddress);
    if (pImageImportSection == nullptr)
    {
        LOG("\n[-] An error when trying to retrieve PE imports!\n");
        return PE_ERROR_PARSING;
    }
    LOGF_DEBUG("[DEBUG] Found import section: %p\n", (void*)pImageImportSection);
    LOGF_DEBUG("[DEBUG] Section name: %.8s\n", pImageImportSection->Name);
    LOGF_DEBUG("[DEBUG] Section VirtualAddress: 0x%lX\n", (unsigned long)pImageImportSection->VirtualAddress);
    LOGF_DEBUG("[DEBUG] Section PointerToRawData: 0x%lX\n", (unsigned long)pImageImportSection->PointerToRawData);
    DWORD_PTR dRawOffset = (DWORD_PTR)pFileInfo->dosHeader + pImageImportSection->PointerToRawData;
    const auto pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dRawOffset + (dImportAddress - pImageImportSection->VirtualAddress));
    LOGF_DEBUG("[DEBUG] dRawOffset: %p\n", (void*)dRawOffset);
    LOGF_DEBUG("[DEBUG] pImageImportDescriptor: %p\n", (void*)pImageImportDescriptor);
    if (pImageImportDescriptor == nullptr)
    {
        LOG("\n[-] An error occurred when trying to retrieve PE imports descriptor!\n");
        return PE_ERROR_PARSING;
    }
    if (pFileInfo->is64Bit)
    {
        LOGF_DEBUG("[DEBUG] Calling GetImports64\n");
        GetImports64(pImageImportDescriptor, dRawOffset, pImageImportSection);
    }
    else
    {
        LOGF_DEBUG("[DEBUG] Calling GetImports32\n");
        GetImports32(pImageImportDescriptor, dRawOffset, pImageImportSection);
    }
    LOGF("\n[+] IMPORT TABLE ANALYSIS SUMMARY\n");
    LOGF("\tArchitecture: %s\n", pFileInfo->is64Bit ? "x64" : "x86");
    LOGF("\tImport table appears to be: ");
    bool hasObfuscatedImports = false;
    if (pImageImportDescriptor->Name == 0) {
        LOGF("Empty or corrupted\n");
        hasObfuscatedImports = true;
    } else {
        LOGF("Populated\n");
    }
    if (hasObfuscatedImports) {
        LOGF("\t[MALWARE INDICATOR] Import table shows signs of obfuscation or corruption\n");
        LOGF("\t                   This is commonly used by malware to evade analysis\n");
    } else {
        LOGF("\t[INFO] Import table appears normal\n");
    }
    return PE_SUCCESS;
}
int ParseExports(PPE_FILE_INFO pFileInfo)
{
    if (!pFileInfo || !pFileInfo->ntHeader) {
        return PE_ERROR_INVALID_PE;
    }
    PIMAGE_DATA_DIRECTORY pDataDirectory;
    PIMAGE_SECTION_HEADER pSectionHeader;
    DWORD_PTR dExportAddress;
    if (pFileInfo->is64Bit)
    {
        const auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo->ntHeader;
        pDataDirectory = pNtHeader64->OptionalHeader.DataDirectory;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader64->FileHeader.SizeOfOptionalHeader);
        dExportAddress = pDataDirectory[0].VirtualAddress;
    }
    else
    {
        const auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo->ntHeader;
        pDataDirectory = pNtHeader32->OptionalHeader.DataDirectory;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader32->FileHeader.SizeOfOptionalHeader);
        dExportAddress = pDataDirectory[0].VirtualAddress;
    }
    if (dExportAddress == 0) {
        printf("\n[-] No export table found!\n");
        return PE_SUCCESS;
    }
    const PIMAGE_SECTION_HEADER pImageExportSection = GetExportSection(pSectionHeader,
                                                                       pFileInfo->ntHeader->FileHeader.NumberOfSections,
                                                                       dExportAddress);
    if (pImageExportSection == nullptr)
    {
        printf("\n[-] An error when trying to retrieve PE exports!\n");
        return PE_ERROR_PARSING;
    }
    DWORD_PTR dRawOffset = (DWORD_PTR)pFileInfo->dosHeader + pImageExportSection->PointerToRawData;
    const auto pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dRawOffset + (dExportAddress - pImageExportSection->VirtualAddress));
    GetExports(pImageExportDirectory, dRawOffset, pImageExportSection);
    return PE_SUCCESS;
}
