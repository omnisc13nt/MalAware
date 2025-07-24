#include "peFileHandler.h"
#include <fstream>
#include <iostream>
#include <memory>
struct FileContentDeleter {
    void operator()(void* ptr) const {
        free(ptr);
    }
};
int LoadPEFile(const char* filePath, PPE_FILE_INFO fileInfo)
{
    if (!filePath || !fileInfo) {
        return PE_ERROR_INVALID_PE;
    }
    memset(fileInfo, 0, sizeof(PE_FILE_INFO));
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        fprintf(stderr, "[-] Error: Unable to open PE file: %s\n", filePath);
        return PE_ERROR_FILE_OPEN;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size <= 0) {
        fprintf(stderr, "[-] Error: Invalid PE file size for: %s\n", filePath);
        file.close();
        return PE_ERROR_FILE_OPEN;
    }
    std::unique_ptr<void, FileContentDeleter> fileContent(malloc(static_cast<size_t>(size)));
    if (!fileContent) {
        fprintf(stderr, "[-] Error: Memory allocation failed for PE file: %s\n", filePath);
        file.close();
        return PE_ERROR_MEMORY_ALLOCATION;
    }
    if (!file.read(static_cast<char*>(fileContent.get()), size)) {
        fprintf(stderr, "[-] Error: Failed to read PE file content: %s\n", filePath);
        file.close();
        return PE_ERROR_FILE_OPEN;
    }
    fileInfo->fileContent = fileContent.release();
    fileInfo->fileSize = static_cast<DWORD>(size);
    file.close();
    return ValidatePEFile(fileInfo);
}
void CleanupPEFile(PPE_FILE_INFO fileInfo)
{
    if (fileInfo && fileInfo->fileContent != nullptr) {
        free(fileInfo->fileContent);
        fileInfo->fileContent = nullptr;
    }
}
int ValidatePEFile(PPE_FILE_INFO fileInfo)
{
    if (!fileInfo || !fileInfo->fileContent) {
        return PE_ERROR_INVALID_PE;
    }
    fileInfo->dosHeader = (PIMAGE_DOS_HEADER)fileInfo->fileContent;
    if (fileInfo->dosHeader == nullptr || fileInfo->dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[-] Invalid DOS header or DOS signature!\n");
        return PE_ERROR_INVALID_PE;
    }
    fileInfo->ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileInfo->fileContent + fileInfo->dosHeader->e_lfanew);
    if (fileInfo->ntHeader == nullptr || fileInfo->ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[-] Invalid NT header or NT signature!\n");
        return PE_ERROR_INVALID_PE;
    }
    if (fileInfo->ntHeader->OptionalHeader.OptionalHeader64.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        fileInfo->is64Bit = TRUE;
    }
    else if (fileInfo->ntHeader->OptionalHeader.OptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        fileInfo->is64Bit = FALSE;
    }
    else
    {
        printf("[-] Unknown PE architecture!\n");
        return PE_ERROR_INVALID_PE;
    }
    return PE_SUCCESS;
}
