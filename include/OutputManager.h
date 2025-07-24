#ifndef OUTPUT_MANAGER_H
#define OUTPUT_MANAGER_H

#include <string>
#include <vector>

enum class OutputLevel {
    MINIMAL = 0,
    SUMMARY = 1,
    STANDARD = 2,
    DETAILED = 3,
    FULL = 4
};

enum class AnalysisMode {
    QUICK = 0,
    SECURITY = 1,
    MALWARE = 2,
    FORENSIC = 3,
    ALL = 4
};

class OutputManager {
private:
    OutputLevel outputLevel;
    AnalysisMode analysisMode;
    bool showTimestamps;
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


    void setOutputLevel(OutputLevel level);
    void setAnalysisMode(AnalysisMode mode);
    void enableSection(const std::string& section);
    void disableSection(const std::string& section);
    void parseCommandLineOptions(int argc, char* argv[]);


    bool shouldShowSection(const std::string& section) const;
    bool shouldShowBasicPEInfo() const;
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


    std::string formatHeader(const std::string& title) const;
    std::string formatSubHeader(const std::string& title) const;
    std::string formatThreat(const std::string& threat, int severity) const;
    std::string formatInfo(const std::string& info) const;
    std::string formatWarning(const std::string& warning) const;
    std::string formatError(const std::string& error) const;


    void printUsage() const;
    void printAvailableOptions() const;


    OutputLevel getOutputLevel() const { return outputLevel; }
    AnalysisMode getAnalysisMode() const { return analysisMode; }
};

#endif
