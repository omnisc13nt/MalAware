#include <cstring>
#include "../include/peSectionParser.h"

// Helper: Convert RVA to file offset using section table
DWORD_PTR RvaToFileOffset(DWORD_PTR rva, PIMAGE_SECTION_HEADER pSectionHeader, int nNumberOfSections)
{
    for (int i = 0; i < nNumberOfSections; ++i)
    {
        const auto pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));
        if (rva >= pCurrentSectionHeader->VirtualAddress &&
            rva < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
        {
            DWORD_PTR offset = (DWORD_PTR)pCurrentSectionHeader->PointerToRawData + (rva - pCurrentSectionHeader->VirtualAddress);
            // Basic bounds check: offset must be >= PointerToRawData and < PointerToRawData + SizeOfRawData
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
                  [[maybe_unused]] DWORD_PTR dRawOffset, 
                  PIMAGE_SECTION_HEADER pImageImportSection)
{
    LOG("\n[+] IMPORTED DLL\n");
    LOGF("[DEBUG] Starting 32-bit import parsing\n");
    LOGF("[DEBUG] pImageImportDescriptor: %p\n", (void*)pImageImportDescriptor);
    LOGF("[DEBUG] pImageImportSection: %p\n", (void*)pImageImportSection);
    
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
    
    LOGF("[DEBUG] g_NumberOfSections: %d\n", g_NumberOfSections);
    LOGF("[DEBUG] g_SectionHeader: %p\n", (void*)g_SectionHeader);
    
    if (!g_SectionHeader) {
        LOG("[-] ERROR: g_SectionHeader is null\n");
        return;
    }
    
    // Get the file base address
    DWORD_PTR fileBase = (DWORD_PTR)pImageImportDescriptor - (DWORD_PTR)pImageImportSection->PointerToRawData;
    LOGF("[DEBUG] fileBase calculated as: %p\n", (void*)fileBase);
    
    int dllCount = 0;
    int maxDlls = 100; // Prevent infinite loops
    
    LOGF("[DEBUG] Starting import descriptor loop\n");
    while (pImageImportDescriptor->Name != 0 && maxDlls-- > 0)
    {
        LOGF("[DEBUG] Processing DLL #%d, Name RVA: 0x%X\n", dllCount + 1, (unsigned int)pImageImportDescriptor->Name);
        
        // Get DLL name
        DWORD_PTR dllNameOffset = RvaToFileOffset(pImageImportDescriptor->Name, g_SectionHeader, g_NumberOfSections);
        LOGF("[DEBUG] DLL name offset: 0x%lX\n", (unsigned long)dllNameOffset);
        
        const char* dllName = "[Invalid]";
        if (dllNameOffset > 0)
        {
            dllName = (const char*)(fileBase + dllNameOffset);
            LOGF("[DEBUG] DLL name pointer: %p\n", (void*)dllName);
            // Validate the string
            if (dllName == nullptr || !isValidString(dllName, 256)) {
                LOGF("[DEBUG] DLL name validation failed\n");
                dllName = "[Invalid]";
            } else {
                LOGF("[DEBUG] DLL name validated successfully: %s\n", dllName);
            }
        }
        
        LOGF("\n\tDLL NAME : %s\n", dllName);
        LOGF("\tCharacteristics : 0x%X\n", (unsigned int)pImageImportDescriptor->Characteristics);
        LOGF("\tOriginalFirstThunk : 0x%llX\n", (unsigned long long)pImageImportDescriptor->OriginalFirstThunk);
        LOGF("\tTimeDateStamp : 0x%X\n", (unsigned int)pImageImportDescriptor->TimeDateStamp);
        LOGF("\tForwarderChain : 0x%X\n", (unsigned int)pImageImportDescriptor->ForwarderChain);
        LOGF("\tFirstThunk : 0x%llX\n", (unsigned long long)pImageImportDescriptor->FirstThunk);

        // Parse imported functions
        if (pImageImportDescriptor->OriginalFirstThunk == 0)
        {
            LOGF("\t[!] No OriginalFirstThunk, skipping imported functions.\n");
            ++pImageImportDescriptor;
            ++dllCount;
            continue;
        }

        DWORD_PTR thunkOffset = RvaToFileOffset(pImageImportDescriptor->OriginalFirstThunk, g_SectionHeader, g_NumberOfSections);
        LOGF("[DEBUG] Thunk offset: 0x%lX\n", (unsigned long)thunkOffset);
        
        if (thunkOffset == 0) {
            LOGF("\t[!] Invalid thunk offset, skipping imported functions.\n");
            ++pImageImportDescriptor;
            ++dllCount;
            continue;
        }
        
        auto pOriginalFirstThunk = (PIMAGE_THUNK_DATA64)(fileBase + thunkOffset);
        LOGF("\n\tImported Functions : \n\n");
        
        int funcCount = 0;
        int maxFuncs = 1000; // Prevent infinite loops
        
        LOGF("[DEBUG] Starting function enumeration loop\n");
        while (pOriginalFirstThunk && pOriginalFirstThunk->u1.AddressOfData != 0 && maxFuncs-- > 0)
        {
            LOGF("[DEBUG] Processing function, AddressOfData: 0x%llX\n", (unsigned long long)pOriginalFirstThunk->u1.AddressOfData);
            
            if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
            {
                // Import by ordinal
                LOGF("\t\tOrdinal #%llu\n", (unsigned long long)(pOriginalFirstThunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG64));
                ++funcCount;
            }
            else
            {
                // Import by name
                DWORD_PTR nameOffset = RvaToFileOffset(pOriginalFirstThunk->u1.AddressOfData, g_SectionHeader, g_NumberOfSections);
                LOGF("[DEBUG] Function name offset: 0x%lX\n", (unsigned long)nameOffset);
                
                const char* funcName = "[Invalid]";
                if (nameOffset > 0)
                {
                    const auto pImageImportByName = (PIMAGE_IMPORT_BY_NAME)(fileBase + nameOffset);
                    LOGF("[DEBUG] Function name pointer: %p\n", (void*)pImageImportByName);
                    
                    if (pImageImportByName && isValidString((const char*)pImageImportByName->Name, 256))
                    {
                        funcName = (const char*)pImageImportByName->Name;
                        LOGF("[DEBUG] Function name: %s\n", funcName);
                    }
                }
                LOGF("\t\t%s\n", funcName);
                ++funcCount;
            }
            ++pOriginalFirstThunk;
        }
        
        if (funcCount == 0)
            LOGF("\t\t[!] No imported functions found for this DLL.\n");
        else
            LOGF("\t\t[+] Found %d imported functions.\n", funcCount);
            
        ++pImageImportDescriptor;
        ++dllCount;
        LOGF("[DEBUG] Finished processing DLL #%d\n", dllCount);
    }
    
    LOGF("\n[+] Total imported DLLs: %d\n", dllCount);
    LOGF("[DEBUG] GetImports64 completed successfully\n");
}

void GetImports64(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor, 
                  DWORD_PTR dRawOffset, 
                  PIMAGE_SECTION_HEADER pImageImportSection)
{
    LOGF("\n[+] IMPORTED DLL\n");
    LOGF("[DEBUG] Starting 64-bit import parsing\n");
    LOGF("[DEBUG] pImageImportDescriptor: %p\n", (void*)pImageImportDescriptor);
    LOGF("[DEBUG] pImageImportSection: %p\n", (void*)pImageImportSection);
    LOGF("[DEBUG] dRawOffset: %p\n", (void*)dRawOffset);
    
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
    
    LOGF("[DEBUG] g_NumberOfSections: %d\n", g_NumberOfSections);
    LOGF("[DEBUG] g_SectionHeader: %p\n", (void*)g_SectionHeader);
    
    if (!g_SectionHeader) {
        LOGF("[-] ERROR: g_SectionHeader is null\n");
        return;
    }
    
    // Get the file base address - this should be the base of the loaded PE file
    // dRawOffset points to the start of the import section data
    // We need to calculate the base by subtracting the section's file offset

    // Debugging note:
    // DWORD_PTR fileBase = (DWORD_PTR)pImageImportDescriptor - (DWORD_PTR)pImageImportSection->PointerToRawData;
    // This was the wrong one, AAAAAAAAAAHHHHHHHHHHHHHHHHHHHHHHHHHHHHHhh - migs
    // Time spent on this shit - 3 hours, goodluck on the other ones


    DWORD_PTR fileBase = dRawOffset - pImageImportSection->PointerToRawData;
    LOGF("[DEBUG] fileBase calculated as: %p\n", (void*)fileBase);
    
    int dllCount = 0;
    int maxDlls = 100; // Prevent infinite loops
    
    LOGF("[DEBUG] Starting while loop, checking pImageImportDescriptor->Name: 0x%X", (unsigned int)pImageImportDescriptor->Name);
    
    while (pImageImportDescriptor->Name != 0 && maxDlls-- > 0)
    {
        LOGF("[DEBUG] Processing DLL at iteration %d", dllCount);
        // Get DLL name
        DWORD_PTR dllNameOffset = RvaToFileOffset(pImageImportDescriptor->Name, g_SectionHeader, g_NumberOfSections);
        LOGF("[DEBUG] DLL name offset: 0x%llX", (unsigned long long)dllNameOffset);
        
        static char safeDllName[256];
        strcpy(safeDllName, "[Invalid]");
        
        if (dllNameOffset > 0)
        {
            const char* dllNamePtr = (const char*)(fileBase + dllNameOffset);
            LOGF("[DEBUG] DLL name pointer: %p", dllNamePtr);
            
            // Simple validation: just check if it's not null and try to read first few bytes
            if (dllNamePtr != nullptr) {
                LOGF("[DEBUG] Attempting to read DLL name...");
                
                // Very simple approach - just copy a few bytes manually
                bool hasValidData = false;
                
                // Check if we can safely read the first 4 bytes
                if (dllNameOffset + 4 < 0x100000) { // Basic sanity check
                    char temp[256];
                    temp[0] = '\0';
                    
                    // Manually copy up to 50 characters
                    for (int i = 0; i < 50; ++i) {
                        char c = dllNamePtr[i];
                        if (c == '\0') {
                            temp[i] = '\0';
                            hasValidData = (i > 0);
                            break;
                        }
                        if (c >= 32 && c <= 126) { // Printable ASCII
                            temp[i] = c;
                        } else {
                            temp[i] = '?';
                        }
                    }
                    temp[49] = '\0'; // Ensure null termination
                    
                    if (hasValidData && strlen(temp) > 0) {
                        strcpy(safeDllName, temp);
                        LOGF("[DEBUG] Successfully read DLL name: %s", safeDllName);
                    } else {
                        LOGF("[DEBUG] No valid DLL name found, using [Invalid]");
                        strcpy(safeDllName, "[Invalid]");
                    }
                } else {
                    LOGF("[DEBUG] DLL name offset out of bounds, using [Invalid]");
                    strcpy(safeDllName, "[Invalid]");
                }
            } else {
                LOGF("[DEBUG] DLL name pointer is NULL, using [Invalid]");
            }
        } else {
            LOGF("[DEBUG] dllNameOffset is 0, using [Invalid]");
        }
        
        const char* dllName = safeDllName;
        
        printf("\n\tDLL NAME : %s\n", dllName);
        printf("\tCharacteristics : 0x%X\n", (unsigned int)pImageImportDescriptor->Characteristics);
        printf("\tOriginalFirstThunk : 0x%llX\n", (unsigned long long)pImageImportDescriptor->OriginalFirstThunk);
        printf("\tTimeDateStamp : 0x%X\n", (unsigned int)pImageImportDescriptor->TimeDateStamp);
        printf("\tForwarderChain : 0x%X\n", (unsigned int)pImageImportDescriptor->ForwarderChain);
        printf("\tFirstThunk : 0x%llX\n", (unsigned long long)pImageImportDescriptor->FirstThunk);

        // Parse imported functions
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
        int maxFuncs = 1000; // Prevent infinite loops
        
        while (pOriginalFirstThunk && pOriginalFirstThunk->u1.AddressOfData != 0 && maxFuncs-- > 0)
        {
            if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
            {
                // Import by ordinal
                printf("\t\tOrdinal #%llu\n", (unsigned long long)(pOriginalFirstThunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG64));
                ++funcCount;
            }
            else
            {
                // Import by name
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
    LOGF("[DEBUG] ParseImports called\n");
    
    if (!pFileInfo || !pFileInfo->pNtHeader) {
        LOG("[-] ERROR: Invalid pFileInfo or pNtHeader in ParseImports\n");
        return PE_ERROR_INVALID_PE;
    }

    LOGF("[DEBUG] pFileInfo: %p, pNtHeader: %p, bIs64Bit: %s\n", 
         (void*)pFileInfo, (void*)pFileInfo->pNtHeader, pFileInfo->bIs64Bit ? "true" : "false");

    PIMAGE_DATA_DIRECTORY pDataDirectory;
    PIMAGE_SECTION_HEADER pSectionHeader;
    DWORD_PTR dImportAddress;

    if (pFileInfo->bIs64Bit)
    {
        LOGF("[DEBUG] Processing 64-bit PE file\n");
        const auto pNtHeader64 = (PIMAGE_NT_HEADERS64)pFileInfo->pNtHeader;
        pDataDirectory = pNtHeader64->OptionalHeader.DataDirectory;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader64->FileHeader.SizeOfOptionalHeader);
        dImportAddress = pDataDirectory[1].VirtualAddress;
        LOGF("[DEBUG] 64-bit import address: 0x%lX\n", (unsigned long)dImportAddress);
    }
    else
    {
        LOGF("[DEBUG] Processing 32-bit PE file\n");
        const auto pNtHeader32 = (PIMAGE_NT_HEADERS32)pFileInfo->pNtHeader;
        pDataDirectory = pNtHeader32->OptionalHeader.DataDirectory;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader32->FileHeader.SizeOfOptionalHeader);
        dImportAddress = pDataDirectory[1].VirtualAddress;
        LOGF("[DEBUG] 32-bit import address: 0x%lX\n", (unsigned long)dImportAddress);
    }

    if (dImportAddress == 0) {
        LOG("\n[-] No import table found!\n");
        return PE_SUCCESS;
    }

    LOGF("[DEBUG] Looking for import section containing RVA 0x%lX\n", (unsigned long)dImportAddress);
    const PIMAGE_SECTION_HEADER pImageImportSection = GetSections(pSectionHeader, 
                                                                  pFileInfo->pNtHeader->FileHeader.NumberOfSections, 
                                                                  dImportAddress);
    if (pImageImportSection == nullptr)
    {
        LOG("\n[-] An error when trying to retrieve PE imports!\n");
        return PE_ERROR_PARSING;
    }

    LOGF("[DEBUG] Found import section: %p\n", (void*)pImageImportSection);
    LOGF("[DEBUG] Section name: %.8s\n", pImageImportSection->Name);
    LOGF("[DEBUG] Section VirtualAddress: 0x%lX\n", (unsigned long)pImageImportSection->VirtualAddress);
    LOGF("[DEBUG] Section PointerToRawData: 0x%lX\n", (unsigned long)pImageImportSection->PointerToRawData);

    DWORD_PTR dRawOffset = (DWORD_PTR)pFileInfo->pDosHeader + pImageImportSection->PointerToRawData;
    const auto pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dRawOffset + (dImportAddress - pImageImportSection->VirtualAddress));
    
    LOGF("[DEBUG] dRawOffset: %p\n", (void*)dRawOffset);
    LOGF("[DEBUG] pImageImportDescriptor: %p\n", (void*)pImageImportDescriptor);
    
    if (pImageImportDescriptor == nullptr)
    {
        LOG("\n[-] An error occurred when trying to retrieve PE imports descriptor!\n");
        return PE_ERROR_PARSING;
    }

    if (pFileInfo->bIs64Bit)
    {
        LOGF("[DEBUG] Calling GetImports64\n");
        GetImports64(pImageImportDescriptor, dRawOffset, pImageImportSection);
    }
    else
    {
        LOGF("[DEBUG] Calling GetImports32\n");
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
