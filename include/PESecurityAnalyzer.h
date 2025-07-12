#pragma once

#include "peCommon.h"
#include "outputCapture.h"
#include <vector>
#include <string>

/**
 * Advanced security analysis for PE files
 * Implements entropy analysis, packer detection, and security features extraction
 */
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
    
    // Entropy analysis
    std::vector<EntropyResult> calculateSectionEntropy();
    double calculateEntropy(const BYTE* data, size_t size);
    
    // Security features extraction
    SecurityFeatures extractSecurityFeatures();
    
    // Packer detection
    PackerInfo detectPacker();
    
    // Overlay detection
    OverlayInfo detectOverlay();
    
    // Anomaly detection
    std::vector<std::string> detectAnomalies();
    
    // Print analysis results
    void printEntropyAnalysis();
    void printSecurityFeatures();
    void printPackerInfo();
    void printOverlayInfo();
    void printAnomalies();
    
    // JSON output
    std::string toJson() const;

private:
    PPE_FILE_INFO pFileInfo_;
    std::vector<EntropyResult> entropyResults_;
    SecurityFeatures securityFeatures_;
    PackerInfo packerInfo_;
    OverlayInfo overlayInfo_;
    std::vector<std::string> anomalies_;
    
    // Helper methods
    bool isHighEntropy(double entropy);
    bool isLowEntropy(double entropy);
    std::string getPackerSignature(const BYTE* data, size_t size);
    bool checkCommonPackerSignatures(const BYTE* data, size_t size);
    DWORD getFileSize();
    DWORD getLastSectionEnd();
};
