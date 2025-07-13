#pragma once

#include "peCommon.h"
#include <vector>
#include <sstream>


typedef uint64_t ULONGLONG;



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
        int suspicionLevel;  
    };

    
    static TLSInfo analyzeTLS(PPE_FILE_INFO pFileInfo);
    
    
    static std::string generateTLSReport(const TLSInfo& tlsInfo);
    
    
    static bool hasTLSDirectory(PPE_FILE_INFO pFileInfo);
    
    
    static std::vector<DWORD_PTR> extractTLSCallbacks(PPE_FILE_INFO pFileInfo);
    
    
    static bool isCallbackSuspicious(DWORD_PTR callback, PPE_FILE_INFO pFileInfo);
    
    
    static void logTLSAnalysis(const TLSInfo& tlsInfo);

private:
    
    static PIMAGE_TLS_DIRECTORY32 getTLSDirectory32(PPE_FILE_INFO pFileInfo);
    static PIMAGE_TLS_DIRECTORY64 getTLSDirectory64(PPE_FILE_INFO pFileInfo);
    
    static std::string analyzeCallbackPattern(const std::vector<DWORD_PTR>& callbacks);
    
    
    static bool isAddressInExecutableSection(DWORD_PTR address, PPE_FILE_INFO pFileInfo);
    static std::string getCallbackLocationDescription(DWORD_PTR callback, PPE_FILE_INFO pFileInfo);
};
