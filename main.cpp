#include "include/peSectionParser.h"
#include "include/peFileHandler.h"
#include "include/peParser.h"
#include "include/PEResourceParser.h"
#include <iostream>

// Globals for import/export parsing
int g_NumberOfSections = 0;
PIMAGE_SECTION_HEADER g_SectionHeader = nullptr;

int main(int argc, char* argv[])
{
    // Initialize logging
    Logger::init("Logs.txt");
    
    if (argc != 2)
    {
        LOGF("[HELP] Usage: %s <PE_file_path>\n", argv[0]);
        Logger::close();
        return PE_ERROR_INVALID_PE;
    }

    LOGF("[INFO] Starting PE file analysis for: %s\n", argv[1]);
    
    PE_FILE_INFO fileInfo;
    
    // Load and validate PE file
    int result = LoadPEFile(argv[1], &fileInfo);
    if (result != PE_SUCCESS)
    {
        LOGF("[-] ERROR: Failed to load PE file: %s (Error code: %d)\n", argv[1], result);
        Logger::close();
        return result;
    }

    LOGF("[+] Successfully loaded PE file: %s\n", argv[1]);
    LOGF("[+] Architecture: %s\n", fileInfo.bIs64Bit ? "x64" : "x86");

    // Set globals for import/export parsing
    if (fileInfo.bIs64Bit)
    {
        auto pNtHeader64 = (PIMAGE_NT_HEADERS64)fileInfo.pNtHeader;
        g_NumberOfSections = pNtHeader64->FileHeader.NumberOfSections;
        g_SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader64->FileHeader.SizeOfOptionalHeader);
    }
    else
    {
        auto pNtHeader32 = (PIMAGE_NT_HEADERS32)fileInfo.pNtHeader;
        g_NumberOfSections = pNtHeader32->FileHeader.NumberOfSections;
        g_SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader32->FileHeader.SizeOfOptionalHeader);
    }

    // Parse PE file
    result = ParsePEFile(&fileInfo);
    if (result != PE_SUCCESS)
    {
        LOGF("[-] ERROR: Failed to parse PE file! (Error code: %d)\n", result);
        CleanupPEFile(&fileInfo);
        Logger::close();
        return result;
    }

    LOG("\n[+] PE file parsing completed successfully!\n");

    // Resource parsing and display
    try {
        PEResourceParser resourceParser(fileInfo.hFileContent, fileInfo.pNtHeader);
        resourceParser.parseResources();
        resourceParser.printResources();
        LOG("[+] Resource parsing completed successfully!\n");
    } catch (const std::exception& e) {
        LOGF("[-] ERROR: Resource parsing failed: %s\n", e.what());
    } catch (...) {
        LOG("[-] ERROR: Unknown error during resource parsing\n");
    }

    // Cleanup
    CleanupPEFile(&fileInfo);
    LOG("[+] PE file analysis completed successfully!\n");
    Logger::close();
    return PE_SUCCESS;
}
