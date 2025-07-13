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
        bool aslr;              // Address Space Layout Randomization
        bool dep;               // Data Execution Prevention  
        bool seh;               // Structured Exception Handling
        bool cfg;               // Control Flow Guard
        bool isolationAware;    // Isolation Aware
        bool nxCompat;          // NX Compatible
        bool dynamicBase;       // Dynamic Base
        bool forceIntegrity;    // Force Integrity
        bool terminalServer;    // Terminal Server Aware
        bool largeAddress;      // Large Address Aware
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
    
    std::string toJson() const;

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
