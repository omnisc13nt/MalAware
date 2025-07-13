#include "include/peSectionParser.h"
#include "include/peFileHandler.h"
#include "include/peParser.h"
#include "include/PEResourceParser.h"
#include "include/PESecurityAnalyzer.h"
#include "include/PEDigitalSignatureAnalyzer.h"
#include "include/PEDebugInfoAnalyzer.h"
#include "include/PEHashCalculator.h"
#include "include/PETLSAnalyzer.h"
#include "include/PEMalwareAnalysisEngine.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <cstdarg>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#define dup_fd _dup
#define dup2_fd _dup2
#define close_fd _close
#define fileno_fd _fileno
#else
#include <unistd.h>
#define dup_fd dup
#define dup2_fd dup2
#define close_fd close
#define fileno_fd fileno
#endif

int g_original_stdout = -1;
FILE* g_output_file = nullptr;

int g_NumberOfSections = 0;
PIMAGE_SECTION_HEADER g_SectionHeader = nullptr;
int g_CorruptedImports = 0;
int g_InvalidDLLNames = 0;

int main(int argc, char* argv[])
{
    
    Logger::init("Logs.txt", "ParseOutput.txt");
    
    g_output_file = fopen("ParseResults.txt", "w");
    if (g_output_file) {
        auto now = std::time(nullptr);
        auto localTime = std::localtime(&now);
        fprintf(g_output_file, "=== PE Parser Results - %s===\n\n", std::asctime(localTime));
        fflush(g_output_file);
    }
    
    if (argc < 2 || argc > 4)
    {
        LOGF("[HELP] Usage: %s <PE_file_path> [-o output_file]\n", argv[0]);
        LOGF("[HELP] Example: %s sample.exe -o analysis_report.txt\n", argv[0]);
        
        if (g_output_file) {
            fclose(g_output_file);
            g_output_file = nullptr;
        }
        Logger::close();
        return PE_ERROR_INVALID_PE;
    }

    std::string inputFile = argv[1];
    std::string outputFile = "ParseResults.txt";
    
    // Parse command line arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outputFile = argv[i + 1];
            i++; // Skip next argument since it's the output filename
        }
    }
    
    // Close the default output file and open the specified one
    if (g_output_file) {
        fclose(g_output_file);
    }
    g_output_file = fopen(outputFile.c_str(), "w");
    if (g_output_file) {
        auto now = std::time(nullptr);
        auto localTime = std::localtime(&now);
        fprintf(g_output_file, "=== PE Parser Results - %s===\n\n", std::asctime(localTime));
        fflush(g_output_file);
    }

    LOGF("[INFO] Starting PE file analysis for: %s\n", inputFile.c_str());
    LOGF("[INFO] Output will be saved to: %s\n", outputFile.c_str());
    
    PE_FILE_INFO fileInfo;
    
    int result = LoadPEFile(inputFile.c_str(), &fileInfo);
    if (result != PE_SUCCESS)
    {
        LOGF("[-] ERROR: Failed to load PE file: %s (Error code: %d)\n", inputFile.c_str(), result);
        Logger::close();
        return result;
    }

    LOGF("[+] Successfully loaded PE file: %s\n", inputFile.c_str());
    LOGF("[+] Architecture: %s\n", fileInfo.bIs64Bit ? "x64" : "x86");

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

    result = ParsePEFile(&fileInfo);
    if (result != PE_SUCCESS)
    {
        LOGF("[-] ERROR: Failed to parse PE file! (Error code: %d)\n", result);
        CleanupPEFile(&fileInfo);
        Logger::close();
        return result;
    }

    LOG("\n[+] PE file parsing completed successfully!\n");

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

    try {
        PESecurityAnalyzer securityAnalyzer(&fileInfo);
        
        securityAnalyzer.printEntropyAnalysis();
        securityAnalyzer.printSecurityFeatures();
        securityAnalyzer.printPackerInfo();
        securityAnalyzer.printOverlayInfo();
        securityAnalyzer.printAnomalies();
        
        LOG("[+] Security analysis completed successfully!\n");
    } catch (const std::exception& e) {
        LOGF("[-] ERROR: Security analysis failed: %s\n", e.what());
    } catch (...) {
        LOG("[-] ERROR: Unknown error during security analysis\n");
    }

    try {
        PEDigitalSignatureAnalyzer signatureAnalyzer(&fileInfo);
        
        signatureAnalyzer.analyzeSignature();
        signatureAnalyzer.printSignatureInfo();
        signatureAnalyzer.printCertificateChain();
        signatureAnalyzer.printSecurityCatalog();
        
        LOG("[+] Digital signature analysis completed successfully!\n");
    } catch (const std::exception& e) {
        LOGF("[-] ERROR: Digital signature analysis failed: %s\n", e.what());
    } catch (...) {
        LOG("[-] ERROR: Unknown error during digital signature analysis\n");
    }

    try {
        PEDebugInfoAnalyzer debugAnalyzer(&fileInfo);
        
        debugAnalyzer.analyzeDebugInfo();
        debugAnalyzer.printDebugInfo();
        debugAnalyzer.printDebugDirectories();
        debugAnalyzer.printCodeViewInfo();
        debugAnalyzer.printRichHeaderInfo();
        
        LOG("[+] Debug information analysis completed successfully!\n");
    } catch (const std::exception& e) {
        LOGF("[-] ERROR: Debug information analysis failed: %s\n", e.what());
    } catch (...) {
        LOG("[-] ERROR: Unknown error during debug information analysis\n");
    }

    try {
        PETLSAnalyzer::TLSInfo tlsInfo = PETLSAnalyzer::analyzeTLS(&fileInfo);
        PETLSAnalyzer::logTLSAnalysis(tlsInfo);
        LOG("[+] TLS analysis completed successfully!\n");
    } catch (const std::exception& e) {
        LOGF("[-] ERROR: TLS analysis failed: %s\n", e.what());
    } catch (...) {
        LOG("[-] ERROR: Unknown error during TLS analysis\n");
    }

    try {
        auto malwareResult = PEMalwareAnalysisEngine::analyzeFile(&fileInfo);
        PEMalwareAnalysisEngine::logMalwareAnalysis(malwareResult);
        LOG("[+] Malware analysis completed successfully!\n");
    } catch (const std::exception& e) {
        LOGF("[-] ERROR: Malware analysis failed: %s\n", e.what());
    } catch (...) {
        LOG("[-] ERROR: Unknown error during malware analysis\n");
    }

    try {
        PEHashCalculator hashCalculator(&fileInfo);
        
        hashCalculator.printFileHashes();
        hashCalculator.printFileInfo();
        hashCalculator.printSectionHashes();
        hashCalculator.printOverlayInfo();
        
        LOG("[+] Hash calculation and file analysis completed successfully!\n");
    } catch (const std::exception& e) {
        LOGF("[-] ERROR: Hash calculation failed: %s\n", e.what());
    } catch (...) {
        LOG("[-] ERROR: Unknown error during hash calculation\n");
    }

    CleanupPEFile(&fileInfo);
    LOG("[+] PE file analysis completed successfully!\n");
    
    if (g_output_file) {
        fprintf(g_output_file, "\n=== Analysis Complete ===\n");
        fclose(g_output_file);
        g_output_file = nullptr;
    }
    
    Logger::close();
    return PE_SUCCESS;
}
