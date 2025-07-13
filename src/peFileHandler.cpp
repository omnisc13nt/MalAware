
#include "../include/peFileHandler.h"
#include <fstream>
#include <iostream>
#include <memory>

struct FileContentDeleter {
    void operator()(void* ptr) const {
        free(ptr);
    }
};

int LoadPEFile(const char* lpFilePath, PPE_FILE_INFO pFileInfo)
{
    if (!lpFilePath || !pFileInfo) {
        return PE_ERROR_INVALID_PE;
    }

    memset(pFileInfo, 0, sizeof(PE_FILE_INFO));

    std::ifstream file(lpFilePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        fprintf(stderr, "[-] Error: Unable to open PE file: %s\n", lpFilePath);
        return PE_ERROR_FILE_OPEN;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size <= 0) {
        fprintf(stderr, "[-] Error: Invalid PE file size for: %s\n", lpFilePath);
        file.close();
        return PE_ERROR_FILE_OPEN;
    }

    std::unique_ptr<void, FileContentDeleter> fileContent(malloc(static_cast<size_t>(size)));
    if (!fileContent) {
        fprintf(stderr, "[-] Error: Memory allocation failed for PE file: %s\n", lpFilePath);
        file.close();
        return PE_ERROR_MEMORY_ALLOCATION;
    }

    if (!file.read(static_cast<char*>(fileContent.get()), size)) {
        fprintf(stderr, "[-] Error: Failed to read PE file content: %s\n", lpFilePath);
        file.close();
        return PE_ERROR_FILE_OPEN;
    }

    pFileInfo->hFileContent = fileContent.release();
    pFileInfo->dwFileSize = static_cast<DWORD>(size);
    file.close();

    return ValidatePEFile(pFileInfo);
}

void CleanupPEFile(PPE_FILE_INFO pFileInfo)
{
    if (pFileInfo && pFileInfo->hFileContent != nullptr) {
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
