#pragma once
#include "peCommon.h"
#include "outputCapture.h"
#include <vector>
#include <string>
class PESecurityAnalyzer {
public:
    struct EntropyResult {
        double entropy;
        bool isPacked;
        std::string sectionName;
        DWORD virtualAddress;
        DWORD size;
    };
    struct SecurityFeatures {
        bool aslr;                      
        bool dep;                       
        bool seh;                       
        bool cfg;                       
        bool isolationAware;            
        bool nxCompat;                  
        bool dynamicBase;               
        bool forceIntegrity;            
        bool terminalServer;            
        bool largeAddress;              
        bool hasReturnFlowGuard;        
        bool hasIntelCET;               
        bool hasKernelCFI;              
    };
    struct PackerInfo {
        bool isPacked;
        std::string packerName;
        double confidence;
        std::string indicators;
    };
    struct OverlayInfo {
        bool hasOverlay;
        DWORD overlayOffset;
        DWORD overlaySize;
        double overlayEntropy;
    };
    explicit PESecurityAnalyzer(PPE_FILE_INFO pFileInfo);
    ~PESecurityAnalyzer() = default;
    std::vector<EntropyResult> calculateSectionEntropy();
    double calculateEntropy(const BYTE* data, size_t size);
    SecurityFeatures extractSecurityFeatures();
    PackerInfo detectPacker();
    OverlayInfo detectOverlay();
    std::vector<std::string> detectAnomalies();
    void printEntropyAnalysis();
    void printSecurityFeatures();
    void printPackerInfo();
    void printOverlayInfo();
    void printAnomalies();
private:
    PPE_FILE_INFO pFileInfo_;
    std::vector<EntropyResult> entropyResults_;
    SecurityFeatures securityFeatures_;
    PackerInfo packerInfo_;
    OverlayInfo overlayInfo_;
    std::vector<std::string> anomalies_;
    bool isHighEntropy(double entropy);
    bool isLowEntropy(double entropy);
    std::string getPackerSignature(const BYTE* data, size_t size);
    bool checkCommonPackerSignatures(const BYTE* data, size_t size);
    DWORD getFileSize();
    DWORD getLastSectionEnd();
};
