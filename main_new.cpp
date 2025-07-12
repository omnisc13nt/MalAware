#include "include/pe_file_handler.h"
#include "include/pe_parser.h"
#include <iostream>

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("[HELP] Usage: %s <PE_file_path>\n", argv[0]);
        return PE_ERROR_INVALID_PE;
    }

    PE_FILE_INFO fileInfo;
    
    // Load and validate PE file
    int result = LoadPEFile(argv[1], &fileInfo);
    if (result != PE_SUCCESS)
    {
        printf("[-] Failed to load PE file: %s\n", argv[1]);
        return result;
    }

    printf("[+] Successfully loaded PE file: %s\n", argv[1]);
    printf("[+] Architecture: %s\n", fileInfo.bIs64Bit ? "x64" : "x86");

    // Parse PE file
    result = ParsePEFile(&fileInfo);
    if (result != PE_SUCCESS)
    {
        printf("[-] Failed to parse PE file!\n");
        CleanupPEFile(&fileInfo);
        return result;
    }

    printf("\n[+] PE file parsing completed successfully!\n");

    // Cleanup
    CleanupPEFile(&fileInfo);
    return PE_SUCCESS;
}
