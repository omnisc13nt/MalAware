#pragma once

#include "peCommon.h"
#include <vector>
#include <sstream>

// Additional type definitions needed for TLS structures
typedef uint64_t ULONGLONG;

/**
 * PE TLS (Thread Local Storage) Analyzer
 * Analyzes TLS callbacks and Thread Local Storage directory
 */

// TLS Directory structures (from winnt.h)
typedef struct _IMAGE_TLS_DIRECTORY32 {
    DWORD   StartAddressOfRawData;
    DWORD   EndAddressOfRawData;
    DWORD   AddressOfIndex;
    DWORD   AddressOfCallBacks;
    DWORD   SizeOfZeroFill;
    DWORD   Characteristics;
} IMAGE_TLS_DIRECTORY32, *PIMAGE_TLS_DIRECTORY32;

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;
    ULONGLONG AddressOfCallBacks;
    DWORD     SizeOfZeroFill;
    DWORD     Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

class PETLSAnalyzer {
public:
    struct TLSInfo {
        bool hasTLS;
        DWORD startAddressOfRawData;
        DWORD endAddressOfRawData;
        DWORD addressOfIndex;
        DWORD addressOfCallBacks;
        DWORD sizeOfZeroFill;
        DWORD characteristics;
        std::vector<DWORD_PTR> callbacks;
        std::string analysis;
        bool isSuspicious;
        int suspicionLevel;  // 0-10 scale
    };

    // Main analysis function
    static TLSInfo analyzeTLS(PPE_FILE_INFO pFileInfo);
    
    // Generate detailed TLS report
    static std::string generateTLSReport(const TLSInfo& tlsInfo);
    
    // Check if PE has TLS directory
    static bool hasTLSDirectory(PPE_FILE_INFO pFileInfo);
    
    // Extract TLS callbacks
    static std::vector<DWORD_PTR> extractTLSCallbacks(PPE_FILE_INFO pFileInfo);
    
    // Analyze callback patterns for suspicious behavior
    static bool isCallbackSuspicious(DWORD_PTR callback, PPE_FILE_INFO pFileInfo);
    
    // Detailed logging
    static void logTLSAnalysis(const TLSInfo& tlsInfo);

private:
    // Platform-specific TLS directory getters
    static PIMAGE_TLS_DIRECTORY32 getTLSDirectory32(PPE_FILE_INFO pFileInfo);
    static PIMAGE_TLS_DIRECTORY64 getTLSDirectory64(PPE_FILE_INFO pFileInfo);
    
    static std::string analyzeCallbackPattern(const std::vector<DWORD_PTR>& callbacks);
    
    // Analysis helpers
    static bool isAddressInExecutableSection(DWORD_PTR address, PPE_FILE_INFO pFileInfo);
    static std::string getCallbackLocationDescription(DWORD_PTR callback, PPE_FILE_INFO pFileInfo);
};
