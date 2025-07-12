#pragma once

#include "peCommon.h"
#include "outputCapture.h"
#include <vector>
#include <string>

/**
 * Debug Information Analysis for PE files
 * Parses debug directories and extracts debug information
 */
class PEDebugInfoAnalyzer {
public:
    struct DebugDirectoryEntry {
        DWORD characteristics;
        DWORD timeDateStamp;
        WORD majorVersion;
        WORD minorVersion;
        DWORD type;
        DWORD sizeOfData;
        DWORD addressOfRawData;
        DWORD pointerToRawData;
        std::string typeName;
    };
    
    struct CodeViewInfo {
        std::string signature;
        std::string pdbPath;
        std::string guid;
        DWORD age;
        bool isValid;
    };
    
    struct FPOInfo {
        DWORD startAddress;
        DWORD procedureSize;
        DWORD localVariables;
        DWORD parameters;
        DWORD prologue;
        DWORD savedRegisters;
        bool hasSEH;
        bool useBP;
    };
    
    struct DebugInfo {
        std::vector<DebugDirectoryEntry> debugDirectories;
        CodeViewInfo codeViewInfo;
        std::vector<FPOInfo> fpoInfo;
        std::string compiledWith;
        std::string buildEnvironment;
        bool hasDebugInfo;
        bool isOptimized;
        bool hasSymbols;
    };

    explicit PEDebugInfoAnalyzer(PPE_FILE_INFO pFileInfo);
    ~PEDebugInfoAnalyzer() = default;
    
    // Main analysis methods
    DebugInfo analyzeDebugInfo();
    std::vector<DebugDirectoryEntry> parseDebugDirectories();
    CodeViewInfo parseCodeViewInfo(const BYTE* data, size_t size);
    std::vector<FPOInfo> parseFPOInfo(const BYTE* data, size_t size);
    
    // Compiler identification
    std::string identifyCompiler();
    std::string identifyLinker();
    std::string extractBuildEnvironment();
    
    // Symbol analysis
    bool hasSymbolTable();
    bool hasLineNumbers();
    std::vector<std::string> extractSymbolNames();
    
    // Rich header analysis
    bool hasRichHeader();
    std::string parseRichHeader();
    
    // Print analysis results
    void printDebugInfo();
    void printDebugDirectories();
    void printCodeViewInfo();
    void printCompilerInfo();
    void printSymbolInfo();
    void printRichHeaderInfo();
    
    // JSON output
    std::string toJson() const;
    
    // Utility methods
    static std::string getDebugTypeName(DWORD type);
    static std::string formatGuid(const BYTE* guidBytes);
    static std::string formatTimestamp(DWORD timestamp);

private:
    PPE_FILE_INFO pFileInfo_;
    DebugInfo debugInfo_;
    
    // Helper methods
    PIMAGE_DEBUG_DIRECTORY getDebugDirectory(DWORD* count);
    bool extractDebugData(const DebugDirectoryEntry& entry, BYTE** data, size_t* size);
    bool parseCodeViewPDB70(const BYTE* data, size_t size);
    bool parseCodeViewPDB20(const BYTE* data, size_t size);
    bool parseCodeViewCV50(const BYTE* data, size_t size);
    
    // Rich header helpers
    BYTE* findRichHeader();
    bool validateRichHeader(const BYTE* richData);
    std::string decodeRichHeader(const BYTE* richData, size_t size);
    
    // Compiler detection helpers
    bool checkVCCompiler(const std::string& pdbPath);
    bool checkGCCCompiler();
    bool checkMinGWCompiler();
    bool checkBorlandCompiler();
    std::string extractLinkerVersion();
    
    // Symbol table helpers
    PIMAGE_SYMBOL getSymbolTable(DWORD* count);
    std::string getSymbolName(const IMAGE_SYMBOL& symbol, const char* stringTable);
};
