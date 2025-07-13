#ifndef PE_SUSPICIOUS_TECHNIQUE_ANALYZER_H
#define PE_SUSPICIOUS_TECHNIQUE_ANALYZER_H

#include "peCommon.h"
#include <string>
#include <vector>
#include <ctime>

struct SuspiciousTechnique {
    std::string name;
    std::string description;
    int severity; // 1-10 scale
    std::string evidence;
    std::string mitigation;
};

class PESuspiciousTechniqueAnalyzer {
private:
    std::vector<SuspiciousTechnique> detectedTechniques;
    
    // Analysis methods
    bool analyzeTimestampManipulation(DWORD timestamp, const std::string& filename);
    bool analyzeEntryPointObfuscation(DWORD entryPoint, DWORD imageBase, DWORD sizeOfCode);
    bool analyzeSectionCharacteristics(const std::vector<IMAGE_SECTION_HEADER>& sections);
    bool analyzeImportTableAnomalies(int totalImports, int corruptedImports);
    bool analyzeResourceAnomalies(DWORD resourceSize, DWORD totalFileSize);
    bool analyzePackingIndicators(const std::vector<double>& sectionEntropies);
    bool analyzeAntiAnalysisTechniques(const std::vector<std::string>& importedFunctions);
    bool analyzePEStructureAnomalies(const IMAGE_NT_HEADERS& ntHeaders);
    
    // Helper methods
    std::string timestampToString(DWORD timestamp);
    bool isKnownMalwareTimestamp(DWORD timestamp);
    bool isCommonPackerEntryPoint(DWORD entryPoint);
    double calculateAverageEntropy(const std::vector<double>& entropies);
    std::string getSeverityDescription(int severity) const;
    
public:
    PESuspiciousTechniqueAnalyzer();
    ~PESuspiciousTechniqueAnalyzer();
    
    // Main analysis function
    void analyzeFile(
        const std::string& filename,
        DWORD timestamp,
        DWORD entryPoint,
        DWORD imageBase,
        DWORD sizeOfCode,
        const std::vector<IMAGE_SECTION_HEADER>& sections,
        const std::vector<double>& sectionEntropies,
        int totalImports,
        int corruptedImports,
        DWORD resourceSize,
        DWORD totalFileSize,
        const std::vector<std::string>& importedFunctions,
        bool is64Bit
    );
    
    // Output methods
    void printAnalysis() const;
    void saveAnalysisToFile(const std::string& filename) const;
    
    // Getters
    const std::vector<SuspiciousTechnique>& getDetectedTechniques() const;
    int getTotalSeverityScore() const;
    bool isSuspicious() const;
    std::string getThreatLevel() const;
};

#endif // PE_SUSPICIOUS_TECHNIQUE_ANALYZER_H
