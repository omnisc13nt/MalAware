#include "include/peSectionParser.h"
#include "include/peFileHandler.h"
#include "include/peParser.h"
#include "include/peImportExport.h"
#include "include/PEResourceParser.h"
#include "include/PESecurityAnalyzer.h"
#include "include/PEDigitalSignatureAnalyzer.h"
#include "include/PEDebugInfoAnalyzer.h"
#include "include/PEHashCalculator.h"
#include "include/PETLSAnalyzer.h"
#include "include/PEMalwareAnalysisEngine.h"
#include "include/PESuspiciousTechniqueAnalyzer.h"
#include "include/FuzzyHashCalculator.h"
#include "include/OutputManager.h"
#include "include/AdvancedEntropyAnalyzer.h"
#include "include/EnhancedOutputManager.h"
#include "include/PerformanceMetrics.h"
#include <iostream>
#include <iomanip>
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

// Function declarations
void generateAnalysisSummary(const PE_FILE_INFO& fileInfo, const std::string& inputFile);
int main(int argc, char* argv[])
{
    // Initialize OutputManager first
    OutputManager outputManager;
    
    // Check for help or usage requests
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            outputManager.printUsage();
            return 0;
        }
    }
    
    // Parse command line options
    outputManager.parseCommandLineOptions(argc, argv);
    
    Logger::init("Logs.txt", "ParseOutput.txt");
    g_output_file = fopen("ParseResults.txt", "w");
    if (g_output_file) {
        auto now = std::time(nullptr);
        auto localTime = std::localtime(&now);
        fprintf(g_output_file, "=== PE Parser Results - %s===\n\n", std::asctime(localTime));
        fflush(g_output_file);
    }
    // Find the input file (first non-flag argument)
    std::string inputFile = "";
    std::string outputFile = "";
    std::string outputFormat = "text";
    bool outputToFile = false;
    
    // Find the input file among arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        // Skip flags and their values
        if (arg.front() == '-') {
            // Skip flags that take values
            if ((arg == "-o" || arg == "-f" || arg == "--vt-api-key") && i + 1 < argc) {
                i++; // Skip the value too
            }
            continue;
        }
        
        // This is the input file
        inputFile = arg;
        break;
    }
    
    if (inputFile.empty()) {
        outputManager.printUsage();
        if (g_output_file) {
            fclose(g_output_file);
            g_output_file = nullptr;
        }
        Logger::close();
        return PE_ERROR_INVALID_PE;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outputFile = argv[i + 1];
            outputToFile = true;
            i++; 
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            outputFormat = argv[i + 1];
            i++; 
        }
        // Skip other options as they're handled by OutputManager
    }
    
    if (g_output_file) {
        fclose(g_output_file);
        g_output_file = nullptr;
    }
    
    // Only create output file if -o flag was specified
    if (outputToFile) {
        g_output_file = fopen(outputFile.c_str(), "w");
        if (g_output_file) {
            auto now = std::time(nullptr);
            auto localTime = std::localtime(&now);
            fprintf(g_output_file, "=== PE Parser Results - %s===\n\n", std::asctime(localTime));
            fflush(g_output_file);
        }
        LOGF("[INFO] Starting PE file analysis for: %s\n", inputFile.c_str());
        LOGF("[INFO] Output will be saved to: %s\n", outputFile.c_str());
    } else {
        // Terminal output only
        printf("[INFO] Starting PE file analysis for: %s\n", inputFile.c_str());
        printf("[INFO] Results will be displayed in terminal\n");
    }
    PE_FILE_INFO fileInfo;
    int loadResult = LoadPEFile(inputFile.c_str(), &fileInfo);
    if (loadResult != PE_SUCCESS)
    {
        LOGF("[-] ERROR: Failed to load PE file: %s (Error code: %d)\n", inputFile.c_str(), loadResult);
        Logger::close();
        return loadResult;
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
    PerformanceMetrics perfMetrics;
    perfMetrics.setFileSize(fileInfo.dwFileSize);
    perfMetrics.startAnalysis();
    int parseResult = ParsePEFile(&fileInfo);
    if (parseResult != PE_SUCCESS)
    {
        LOGF("[-] ERROR: Failed to parse PE file! (Error code: %d)\n", parseResult);
        CleanupPEFile(&fileInfo);
        Logger::close();
        return parseResult;
    }
    LOG("\n[+] PE file parsing completed successfully!\n");
    
    // Generate analysis summary
    generateAnalysisSummary(fileInfo, inputFile);
    
    // Resource Analysis (conditional)
    if (outputManager.shouldShowResources()) {
        try {
            perfMetrics.startModule("Resource Analysis");
            PEResourceParser resourceParser(fileInfo.hFileContent, fileInfo.pNtHeader);
            resourceParser.parseResources();
            resourceParser.printResources();
            perfMetrics.endModule("Resource Analysis", true);
            LOG("[+] Resource parsing completed successfully!\n");
        } catch (const std::exception& e) {
            perfMetrics.endModule("Resource Analysis", false);
            LOGF("[-] ERROR: Resource parsing failed: %s\n", e.what());
        } catch (...) {
            perfMetrics.endModule("Resource Analysis", false);
            LOG("[-] ERROR: Unknown error during resource parsing\n");
        }
    }
    
    // Security Analysis (conditional)
    if (outputManager.shouldRunSecurityAnalysis()) {
        try {
            perfMetrics.startModule("Security Analysis");
            PESecurityAnalyzer securityAnalyzer(&fileInfo);
            if (outputManager.shouldShowEntropy()) {
                securityAnalyzer.printEntropyAnalysis();
            }
            securityAnalyzer.printSecurityFeatures();
            securityAnalyzer.printPackerInfo();
            if (outputManager.shouldShowDetails()) {
                securityAnalyzer.printOverlayInfo();
                securityAnalyzer.printAnomalies();
            }
            perfMetrics.endModule("Security Analysis", true);
            LOG("[+] Security analysis completed successfully!\n");
        } catch (const std::exception& e) {
            perfMetrics.endModule("Security Analysis", false);
            LOGF("[-] ERROR: Security analysis failed: %s\n", e.what());
        } catch (...) {
            perfMetrics.endModule("Security Analysis", false);
            LOG("[-] ERROR: Unknown error during security analysis\n");
        }
    }
    
    // Fuzzy Hash Analysis (conditional)
    if (outputManager.shouldShowFuzzyHashes()) {
        try {
            FuzzyHashCalculator fuzzyHashCalc;
            auto fuzzyHashes = fuzzyHashCalc.calculateAllHashes(inputFile);
            LOG("\n[+] FUZZY HASH ANALYSIS\n");
            LOGF("	SSDeep: %s\n", fuzzyHashes.ssdeep.c_str());
            LOGF("	TLSH: %s\n", fuzzyHashes.tlsh.c_str());
            LOGF("	VHash: %s\n", fuzzyHashes.vhash.c_str());
            LOG("[+] Fuzzy hash analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Fuzzy hash analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during fuzzy hash analysis\n");
        }
    }
    
    // Advanced Entropy Analysis (conditional)
    if (outputManager.shouldShowEntropy()) {
        try {
            AdvancedEntropyAnalyzer entropyAnalyzer;
            auto entropyResults = entropyAnalyzer.analyzeFile(inputFile);
            LOG("\n[+] ADVANCED ENTROPY ANALYSIS\n");
            LOGF("	Overall File Entropy: %.2f (Scale: 0.0 = ordered, 8.0 = random)\n", entropyResults.fileOverall.entropy);
            LOGF("	Classification: %s\n", entropyResults.fileOverall.classification.c_str());
            
            // Add entropy context
            if (entropyResults.fileOverall.entropy >= 7.8) {
                LOG("	⚠️  VERY HIGH ENTROPY - Likely packed, encrypted, or compressed\n");
            } else if (entropyResults.fileOverall.entropy >= 7.5) {
                LOG("	⚠️  HIGH ENTROPY - May indicate compression or obfuscation\n");
            } else if (entropyResults.fileOverall.entropy >= 6.0) {
                LOG("	✅ NORMAL ENTROPY - Typical for executable code and data\n");
            } else if (entropyResults.fileOverall.entropy >= 3.0) {
                LOG("	ℹ️  LOW ENTROPY - Contains repetitive data\n");
            } else {
                LOG("	ℹ️  VERY LOW ENTROPY - Mostly padding or zeros\n");
            }
            
            LOGF("	Packing Detected: %s\n", entropyResults.fileOverall.isPacked ? "YES" : "NO");
            LOGF("	Risk Score: %.1f/100\n", entropyResults.riskScore);
            if (outputManager.shouldShowDetails()) {
                for (const auto& section : entropyResults.sections) {
                    LOGF("	Section %s: Entropy %.2f (%s)\n", 
                         section.sectionName.c_str(), 
                         section.result.entropy,
                         section.result.classification.c_str());
                }
            }
            LOG("[+] Enhanced entropy analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Enhanced entropy analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during enhanced entropy analysis\n");
        }
    }
    
    // Digital Signature Analysis (conditional)
    if (outputManager.shouldShowDigitalSignatures()) {
        try {
            perfMetrics.startModule("Digital Signature Analysis");
            PEDigitalSignatureAnalyzer signatureAnalyzer(&fileInfo);
            signatureAnalyzer.analyzeSignature();
            signatureAnalyzer.printSignatureInfo();
            if (outputManager.shouldShowDetails()) {
                signatureAnalyzer.printCertificateChain();
            }
            signatureAnalyzer.printSecurityCatalog();
            perfMetrics.endModule("Digital Signature Analysis", true);
            LOG("[+] Digital signature analysis completed successfully!\n");
        } catch (const std::exception& e) {
            perfMetrics.endModule("Digital Signature Analysis", false);
            LOGF("[-] ERROR: Digital signature analysis failed: %s\n", e.what());
        } catch (...) {
            perfMetrics.endModule("Digital Signature Analysis", false);
            LOG("[-] ERROR: Unknown error during digital signature analysis\n");
        }
    }
    
    // Debug Information Analysis (conditional)
    if (outputManager.shouldShowDebugInfo()) {
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
    }
    
    // TLS Analysis (conditional)
    if (outputManager.shouldShowTLS()) {
        try {
            PETLSAnalyzer::TLSInfo tlsInfo = PETLSAnalyzer::analyzeTLS(&fileInfo);
            PETLSAnalyzer::logTLSAnalysis(tlsInfo);
            LOG("[+] TLS analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: TLS analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during TLS analysis\n");
        }
    }
    
    // Malware Analysis (conditional)
    if (outputManager.shouldRunMalwareAnalysis()) {
        try {
            auto malwareResult = PEMalwareAnalysisEngine::analyzeFile(&fileInfo);
            PEMalwareAnalysisEngine::logMalwareAnalysis(malwareResult);
            LOG("[+] Malware analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Malware analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during malware analysis\n");
        }
    }
    
    // Suspicious Technique Analysis (conditional)
    if (outputManager.shouldShowSuspiciousTechniques()) {
        try {
            PESuspiciousTechniqueAnalyzer techAnalyzer;
        
        // Gather data for analysis
        DWORD timestamp = 0;
        DWORD entryPoint = 0;
        DWORD imageBase = 0;
        DWORD sizeOfCode = 0;
        DWORD resourceSize = 0;
        
        std::vector<IMAGE_SECTION_HEADER> sections;
        std::vector<double> sectionEntropies;
        std::vector<std::string> importedFunctions;
        
        if (fileInfo.bIs64Bit) {
            auto pNtHeader64 = (PIMAGE_NT_HEADERS64)fileInfo.pNtHeader;
            timestamp = pNtHeader64->FileHeader.TimeDateStamp;
            entryPoint = pNtHeader64->OptionalHeader.AddressOfEntryPoint;
            imageBase = static_cast<DWORD>(pNtHeader64->OptionalHeader.ImageBase);
            sizeOfCode = pNtHeader64->OptionalHeader.SizeOfCode;
            
            // Collect section information
            auto pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader64->FileHeader.SizeOfOptionalHeader);
            for (int i = 0; i < pNtHeader64->FileHeader.NumberOfSections; i++) {
                sections.push_back(pSectionHeader[i]);
                // Calculate entropy for each section (simplified)
                double entropy = 6.0; // Default entropy, would need actual calculation
                sectionEntropies.push_back(entropy);
            }
            
            techAnalyzer.analyzeFile(
                inputFile,
                timestamp,
                entryPoint,
                imageBase,
                sizeOfCode,
                sections,
                sectionEntropies,
                0, // totalImports - would need to collect from import analysis
                0, // corruptedImports - would need to collect from import analysis
                resourceSize,
                static_cast<DWORD>(fileInfo.dwFileSize),
                importedFunctions,
                true // is64Bit
            );
        } else {
            auto pNtHeader32 = (PIMAGE_NT_HEADERS32)fileInfo.pNtHeader;
            timestamp = pNtHeader32->FileHeader.TimeDateStamp;
            entryPoint = pNtHeader32->OptionalHeader.AddressOfEntryPoint;
            imageBase = pNtHeader32->OptionalHeader.ImageBase;
            sizeOfCode = pNtHeader32->OptionalHeader.SizeOfCode;
            
            // Collect section information
            auto pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNtHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader32->FileHeader.SizeOfOptionalHeader);
            for (int i = 0; i < pNtHeader32->FileHeader.NumberOfSections; i++) {
                sections.push_back(pSectionHeader[i]);
                // Calculate entropy for each section (simplified)
                double entropy = 6.0; // Default entropy, would need actual calculation
                sectionEntropies.push_back(entropy);
            }
            
            techAnalyzer.analyzeFile(
                inputFile,
                timestamp,
                entryPoint,
                imageBase,
                sizeOfCode,
                sections,
                sectionEntropies,
                0, // totalImports - would need to collect from import analysis
                0, // corruptedImports - would need to collect from import analysis
                resourceSize,
                static_cast<DWORD>(fileInfo.dwFileSize),
                importedFunctions,
                false // is64Bit
            );
        }
        
        techAnalyzer.printAnalysis();
        LOG("[+] Suspicious technique analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Suspicious technique analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during suspicious technique analysis\n");
        }
    }
    
    // Hash Analysis (conditional)
    if (outputManager.shouldShowHashes()) {
        try {
            PEHashCalculator hashCalculator(&fileInfo);
            hashCalculator.printFileHashes();
            hashCalculator.printFileInfo();
            if (outputManager.shouldShowDetails()) {
                hashCalculator.printSectionHashes();
                hashCalculator.printOverlayInfo();
            }
            
            LOG("[+] Hash calculation and file analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Hash calculation failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during hash calculation\n");
        }
    }
    
    try {
        perfMetrics.endAnalysis();
        auto metrics = perfMetrics.generateReport();
        LOG("\n[+] PERFORMANCE METRICS\n");
        LOGF("	Total Analysis Time: %.2f seconds\n", metrics.totalTime);
        if (metrics.peakMemory > 1024) { // Only show if > 1KB
            LOGF("	Peak Memory Usage: %.2f MB\n", metrics.peakMemory / (1024.0 * 1024.0));
        } else {
            LOGF("	Peak Memory Usage: < 1 MB (minimal footprint)\n");
        }
        LOGF("	Performance Grade: %s\n", metrics.performanceGrade.c_str());
        if (!metrics.bottlenecks.empty()) {
            LOG("	Bottlenecks Identified:\n");
            for (const auto& bottleneck : metrics.bottlenecks) {
                LOGF("	  - %s\n", bottleneck.c_str());
            }
        }
        LOG("[+] Performance metrics analysis completed successfully!\n");
    } catch (const std::exception& e) {
        LOGF("[-] ERROR: Performance metrics failed: %s\n", e.what());
    } catch (...) {
        LOG("[-] ERROR: Unknown error during performance metrics\n");
    }
    if (false && outputFormat != "text") { // JSON functionality disabled
        try {
            EnhancedOutputManager outputManager;
            LOG("\n[+] ENHANCED OUTPUT GENERATION\n");
            LOGF("Generating output in %s format...\n", outputFormat.c_str());
            
            // Set output format
            if (outputFormat == "json") {
                outputManager.setOutputFormat(EnhancedOutputManager::OutputFormat::JSON);
                LOG("JSON output format selected\n");
            } else if (outputFormat == "xml") {
                outputManager.setOutputFormat(EnhancedOutputManager::OutputFormat::XML);
                LOG("XML output format selected\n");
            } else if (outputFormat == "csv") {
                outputManager.setOutputFormat(EnhancedOutputManager::OutputFormat::CSV);
                LOG("CSV output format selected\n");
            } else if (outputFormat == "summary") {
                outputManager.setOutputFormat(EnhancedOutputManager::OutputFormat::SUMMARY);
                LOG("Summary output format selected\n");
            }
            
            // Set output file
            outputManager.setOutputFile(outputFile);
            
            // Populate analysis data
            EnhancedOutputManager::AnalysisData data;
            data.fileName = inputFile.substr(inputFile.find_last_of("/\\") + 1);
            data.filePath = inputFile;
            data.fileSize = fileInfo.dwFileSize;
            data.architecture = fileInfo.bIs64Bit ? "x64" : "x86";
            data.compilationTime = fileInfo.pNtHeader->FileHeader.TimeDateStamp;
            data.sectionCount = fileInfo.pNtHeader->FileHeader.NumberOfSections;
            
            // Get entry point and subsystem based on architecture
            if (fileInfo.bIs64Bit) {
                PIMAGE_NT_HEADERS64 pNtHeader64 = (PIMAGE_NT_HEADERS64)fileInfo.pNtHeader;
                data.entryPoint = pNtHeader64->OptionalHeader.AddressOfEntryPoint;
                
                // Get subsystem
                switch(pNtHeader64->OptionalHeader.Subsystem) {
                    case 1: data.subsystem = "Native"; break;
                    case 2: data.subsystem = "GUI"; break;
                    case 3: data.subsystem = "Console"; break;
                    default: data.subsystem = "Unknown"; break;
                }
                
                // Security features
                data.aslrEnabled = (pNtHeader64->OptionalHeader.DllCharacteristics & 0x40) != 0;
                data.depEnabled = (pNtHeader64->OptionalHeader.DllCharacteristics & 0x100) != 0;
                data.sehEnabled = (pNtHeader64->OptionalHeader.DllCharacteristics & 0x400) != 0;
                data.cfgEnabled = (pNtHeader64->OptionalHeader.DllCharacteristics & 0x4000) != 0;
            } else {
                PIMAGE_NT_HEADERS32 pNtHeader32 = (PIMAGE_NT_HEADERS32)fileInfo.pNtHeader;
                data.entryPoint = pNtHeader32->OptionalHeader.AddressOfEntryPoint;
                
                // Get subsystem
                switch(pNtHeader32->OptionalHeader.Subsystem) {
                    case 1: data.subsystem = "Native"; break;
                    case 2: data.subsystem = "GUI"; break;
                    case 3: data.subsystem = "Console"; break;
                    default: data.subsystem = "Unknown"; break;
                }
                
                // Security features
                data.aslrEnabled = (pNtHeader32->OptionalHeader.DllCharacteristics & 0x40) != 0;
                data.depEnabled = (pNtHeader32->OptionalHeader.DllCharacteristics & 0x100) != 0;
                data.sehEnabled = (pNtHeader32->OptionalHeader.DllCharacteristics & 0x400) != 0;
                data.cfgEnabled = (pNtHeader32->OptionalHeader.DllCharacteristics & 0x4000) != 0;
            }
            
            data.nxCompatible = data.depEnabled;
            
            // Collect hash data
            try {
                PEHashCalculator hashCalc(&fileInfo);
                auto hashResult = hashCalc.calculateAllHashes();
                data.md5 = hashResult.md5;
                data.sha1 = hashResult.sha1;
                data.sha256 = hashResult.sha256;
                data.imphash = hashResult.imphash;
                data.ssdeep = hashResult.ssdeep;
                data.tlsh = hashResult.tlsh;
                data.vhash = hashResult.vhash;
                
                // Get section entropy data
                auto sectionHashes = hashCalc.calculateSectionHashes();
                data.overallEntropy = 0.0;
                double totalEntropy = 0.0;
                int validSections = 0;
                
                for (const auto& section : sectionHashes) {
                    if (section.entropy > 0.0) {
                        data.sectionEntropies.push_back({section.sectionName, section.entropy});
                        totalEntropy += section.entropy;
                        validSections++;
                    }
                }
                
                if (validSections > 0) {
                    data.overallEntropy = totalEntropy / validSections;
                }
                
                // Detect packing based on entropy
                data.packingDetected = data.overallEntropy > 7.0;
            } catch (...) {
                // If hash calculation fails, leave fields empty
                data.md5 = "";
                data.sha1 = "";
                data.sha256 = "";
                data.imphash = "";
                data.ssdeep = "";
                data.tlsh = "";
                data.vhash = "";
                data.overallEntropy = 0.0;
                data.packingDetected = false;
            }
            
            // Collect import data (simplified for now)
            try {
                data.importCount = 0;
                data.dllCount = 0;
                data.corruptedImports = 0;
                data.importedDlls.clear();
                
                // Get basic import information from NT headers
                if (fileInfo.bIs64Bit) {
                    PIMAGE_NT_HEADERS64 pNtHeader64 = (PIMAGE_NT_HEADERS64)fileInfo.pNtHeader;
                    if (pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0) {
                        data.dllCount = 1; // At least one import table exists
                        data.importCount = 10; // Default estimate
                    }
                } else {
                    PIMAGE_NT_HEADERS32 pNtHeader32 = (PIMAGE_NT_HEADERS32)fileInfo.pNtHeader;
                    if (pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0) {
                        data.dllCount = 1; // At least one import table exists
                        data.importCount = 10; // Default estimate
                    }
                }
            } catch (...) {
                data.importCount = 0;
                data.dllCount = 0;
                data.corruptedImports = 0;
                data.importedDlls.clear();
            }
            
            // Collect malware analysis data
            try {
                auto malwareResult = PEMalwareAnalysisEngine::analyzeFile(&fileInfo);
                data.riskScore = malwareResult.riskScore;
                data.classification = malwareResult.classification;
                data.recommendation = malwareResult.recommendation;
                
                // Extract threat indicators
                for (const auto& indicator : malwareResult.indicators) {
                    if (indicator.isDetected) {
                        data.threatIndicators.push_back(indicator.category + ": " + indicator.description);
                    }
                }
            } catch (...) {
                data.riskScore = 0;
                data.classification = "Unknown";
                data.recommendation = "Analysis failed";
                data.threatIndicators.clear();
            }
            
            // Performance metrics
            data.analysisTime = perfMetrics.getAnalysisTime();
            data.memoryUsage = perfMetrics.getPeakMemoryUsage();
            
            // Set timestamp
            data.analysisTimestamp = std::to_string(time(nullptr));
            
            // Generate output
            if (outputManager.generateOutput(data)) {
                LOGF("Enhanced output successfully saved to: %s\n", outputFile.c_str());
            } else {
                LOG("[-] ERROR: Failed to write enhanced output file\n");
            }
            
            LOG("[+] Enhanced output generation completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Enhanced output generation failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during enhanced output generation\n");
        }
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

// Function to generate analysis summary
void generateAnalysisSummary(const PE_FILE_INFO& fileInfo, const std::string& inputFile) {
    LOG("\n===============================\n");
    LOG("    ANALYSIS SUMMARY\n");
    LOG("===============================\n");
    
    // Basic file information
    LOGF("File: %s\n", inputFile.c_str());
    LOGF("Size: %.2f MB (%u bytes)\n", 
         fileInfo.dwFileSize / (1024.0 * 1024.0), 
         static_cast<DWORD>(fileInfo.dwFileSize));
    LOGF("Architecture: %s\n", fileInfo.bIs64Bit ? "x64" : "x86");
    
    // File type
    WORD characteristics = fileInfo.pNtHeader->FileHeader.Characteristics;
    std::string fileType = "Unknown";
    if (characteristics & IMAGE_FILE_DLL) {
        fileType = "Dynamic Link Library (DLL)";
    } else if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        fileType = "Executable";
    } else if (characteristics & IMAGE_FILE_SYSTEM) {
        fileType = "System File";
    }
    LOGF("File Type: %s\n", fileType.c_str());
    
    // Quick security indicators
    LOG("\nQuick Security Assessment:\n");
    
    // Check if digitally signed (placeholder - will be determined during actual analysis)
    LOG("🔍 Digital Signature: Will be analyzed below\n");
    LOG("🔍 Entropy Analysis: Will be analyzed below\n");
    LOG("🔍 Packing Detection: Will be analyzed below\n");
    LOG("🔍 Suspicious Patterns: Will be analyzed below\n");
    
    LOG("\n📝 Detailed analysis results follow...\n");
    LOG("===============================\n");
}
