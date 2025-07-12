#include "../include/pe_file_handler.h"
#include <fstream>
#include <iostream>

int LoadPEFile(const char* lpFilePath, PPE_FILE_INFO pFileInfo)
{
    if (!lpFilePath || !pFileInfo) {
        return PE_ERROR_INVALID_PE;
    }

    // Initialize the structure
    memset(pFileInfo, 0, sizeof(PE_FILE_INFO));

    // Open file using standard C++ streams
    std::ifstream file(lpFilePath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        printf("[-] An error occurred when trying to open the PE file!\n");
        return PE_ERROR_FILE_OPEN;
    }

    // Get file size
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (size <= 0)
    {
        printf("[-] An error occurred when trying to get the PE file size!\n");
        file.close();
        return PE_ERROR_FILE_OPEN;
    }

    // Allocate memory for file content
    pFileInfo->hFileContent = malloc(static_cast<size_t>(size));
    if (pFileInfo->hFileContent == nullptr)
    {
        printf("[-] An error occurred when trying to allocate memory for the PE file content!\n");
        file.close();
        return PE_ERROR_MEMORY_ALLOCATION;
    }

    // Read file content
    if (!file.read(static_cast<char*>(pFileInfo->hFileContent), size))
    {
        printf("[-] An error occurred when trying to read the PE file content!\n");
        file.close();
        CleanupPEFile(pFileInfo);
        return PE_ERROR_FILE_OPEN;
    }

    pFileInfo->dwFileSize = static_cast<DWORD>(size);
    file.close();

    return ValidatePEFile(pFileInfo);
}

void CleanupPEFile(PPE_FILE_INFO pFileInfo)
{
    if (pFileInfo && pFileInfo->hFileContent != nullptr)
    {
        free(pFileInfo->hFileContent);
        pFileInfo->hFileContent = nullptr;
    }
}

int ValidatePEFile(PPE_FILE_INFO pFileInfo)
{
    if (!pFileInfo || !pFileInfo->hFileContent) {
        return PE_ERROR_INVALID_PE;
    }

    pFileInfo->pDosHeader = (PIMAGE_DOS_HEADER)pFileInfo->hFileContent;
    if (pFileInfo->pDosHeader == nullptr || pFileInfo->pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[-] Invalid DOS header or DOS signature!\n");
        return PE_ERROR_INVALID_PE;
    }

    pFileInfo->pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pFileInfo->hFileContent + pFileInfo->pDosHeader->e_lfanew);
    if (pFileInfo->pNtHeader == nullptr || pFileInfo->pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[-] Invalid NT header or NT signature!\n");
        return PE_ERROR_INVALID_PE;
    }

    // Determine if it's 64-bit or 32-bit
    if (pFileInfo->pNtHeader->OptionalHeader.OptionalHeader64.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        pFileInfo->bIs64Bit = TRUE;
    }
    else if (pFileInfo->pNtHeader->OptionalHeader.OptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        pFileInfo->bIs64Bit = FALSE;
    }
    else
    {
        printf("[-] Unknown PE architecture!\n");
        return PE_ERROR_INVALID_PE;
    }

    return PE_SUCCESS;
}
