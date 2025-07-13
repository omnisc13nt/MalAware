#ifndef OUTPUT_MANAGER_H
#define OUTPUT_MANAGER_H

#include <string>
#include <vector>

enum class OutputLevel {
    MINIMAL = 0,    // Only critical threats and basic info
    SUMMARY = 1,    // Brief analysis summary
    STANDARD = 2,   // Default level with important details
    DETAILED = 3,   // Comprehensive analysis
    FULL = 4        // Everything including debug info
};

enum class AnalysisMode {
    QUICK = 0,      // Basic PE parsing only
    SECURITY = 1,   // Focus on security analysis
    MALWARE = 2,    // Comprehensive malware analysis
    FORENSIC = 3,   // Full forensic analysis
    ALL = 4         // All analyzers enabled
};

class OutputManager {
private:
    OutputLevel outputLevel;
    AnalysisMode analysisMode;
    bool showTimestamps;
    bool colorOutput;
    bool includeHashes;
    bool includeEntropy;
    bool includeSuspiciousTechniques;
    bool includeImports;
    bool includeExports;
    bool includeResources;
    bool includeDigitalSignatures;
    bool includeTLS;
    bool includeFuzzyHashes;
    bool includeDebugInfo;
    std::vector<std::string> enabledSections;

public:
    OutputManager();
    
    // Configuration methods
    void setOutputLevel(OutputLevel level);
    void setAnalysisMode(AnalysisMode mode);
    void enableSection(const std::string& section);
    void disableSection(const std::string& section);
    void parseCommandLineOptions(int argc, char* argv[]);
    
    // Query methods
    bool shouldShowSection(const std::string& section) const;
    bool shouldShowDetails() const;
    bool shouldShowHashes() const;
    bool shouldShowEntropy() const;
    bool shouldShowSuspiciousTechniques() const;
    bool shouldShowImports() const;
    bool shouldShowExports() const;
    bool shouldShowResources() const;
    bool shouldShowDigitalSignatures() const;
    bool shouldShowTLS() const;
    bool shouldShowFuzzyHashes() const;
    bool shouldShowDebugInfo() const;
    bool shouldRunMalwareAnalysis() const;
    bool shouldRunSecurityAnalysis() const;
    bool shouldRunForensicAnalysis() const;
    
    // Output formatting
    std::string formatHeader(const std::string& title) const;
    std::string formatSubHeader(const std::string& title) const;
    std::string formatThreat(const std::string& threat, int severity) const;
    std::string formatInfo(const std::string& info) const;
    std::string formatWarning(const std::string& warning) const;
    std::string formatError(const std::string& error) const;
    
    // Help and usage
    void printUsage() const;
    void printAvailableOptions() const;
    
    // Getters
    OutputLevel getOutputLevel() const { return outputLevel; }
    AnalysisMode getAnalysisMode() const { return analysisMode; }
    bool isColorEnabled() const { return colorOutput; }
};

#endif // OUTPUT_MANAGER_H
