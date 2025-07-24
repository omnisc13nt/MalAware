#ifndef PE_SUSPICIOUS_TECHNIQUE_ANALYZER_H
#define PE_SUSPICIOUS_TECHNIQUE_ANALYZER_H

#include "peCommon.h"
#include <string>
#include <vector>
#include <map>
#include <ctime>

enum class TechniqueCategory {
    PROCESS_INJECTION,
    PROCESS_HOLLOWING,
    PROCESS_DOPPELGANGING,
    DLL_INJECTION,
    REFLECTIVE_DLL_LOADING,
    ATOM_BOMBING,
    
    ANTI_DEBUGGING,
    ANTI_VM,
    ANTI_SANDBOX,
    CODE_OBFUSCATION,
    PACKING,
    TIMING_ATTACKS,
    ENVIRONMENT_CHECKS,
    
    REGISTRY_PERSISTENCE,
    SCHEDULED_TASK,
    SERVICE_INSTALLATION,
    STARTUP_FOLDER,
    DLL_HIJACKING,
    COM_HIJACKING,
    
    C2_COMMUNICATION,
    DATA_EXFILTRATION,
    DOMAIN_GENERATION,
    TOR_USAGE,
    CRYPTO_MINING,
    
    PRIVILEGE_ESCALATION,
    SYSTEM_INFO_GATHERING,
    CREDENTIAL_THEFT,
    KEYLOGGING,
    SCREEN_CAPTURE,
    
    FILE_ENCRYPTION,
    FILE_DELETION,
    LOG_DELETION,
    BACKUP_DELETION,
    SHADOW_COPY_DELETION,
    
    MEMORY_MANIPULATION,
    HOOK_INSTALLATION,
    ROOTKIT_BEHAVIOR,
    LATERAL_MOVEMENT
};

struct SuspiciousTechnique {
    TechniqueCategory category;
    std::string name;
    std::string description;
    int severity;
    std::string evidence;
    std::string mitigation;
    std::string mitreAttackId;
    float confidence;
};

class PESuspiciousTechniqueAnalyzer {
private:
    std::vector<SuspiciousTechnique> detectedTechniques;
    PPE_FILE_INFO pFileInfo;
    
    static const std::map<TechniqueCategory, std::vector<std::string>> TECHNIQUE_APIS;
    static const std::map<TechniqueCategory, std::vector<std::string>> TECHNIQUE_STRINGS;
    static const std::map<TechniqueCategory, std::string> MITRE_MAPPINGS;

    bool analyzeTimestampManipulation(DWORD timestamp, const std::string& filename);
    bool analyzeEntryPointObfuscation(DWORD entryPoint, DWORD imageBase, DWORD sizeOfCode);
    bool analyzeSectionCharacteristics(const std::vector<IMAGE_SECTION_HEADER>& sections);
    bool analyzeImportTableAnomalies(int totalImports, int corruptedImports);
    bool analyzeResourceAnomalies(DWORD resourceSize, DWORD totalFileSize);
    bool analyzePackingIndicators(const std::vector<double>& sectionEntropies);
    bool analyzeAntiAnalysisTechniques(const std::vector<std::string>& importedFunctions);
    bool analyzePEStructureAnomalies(const IMAGE_NT_HEADERS& ntHeaders);
    
    void detectProcessInjection();
    void detectAntiDebugging();
    void detectAntiVM();
    void detectPacking();
    void detectPersistence();
    void detectNetworkActivity();
    void detectSystemManipulation();
    void detectFileOperations();
    void detectMemoryManipulation();
    void detectRootkitBehavior();
    
    std::string timestampToString(DWORD timestamp);
    bool isKnownMalwareTimestamp(DWORD timestamp);
    bool isCommonPackerEntryPoint(DWORD entryPoint);
    double calculateAverageEntropy(const std::vector<double>& entropies);
    std::string getSeverityDescription(int severity) const;
    std::string getMitreAttackId(TechniqueCategory technique);
    
    void addTechnique(TechniqueCategory category, const std::string& name, 
                     const std::string& description, int severity,
                     const std::string& evidence, const std::string& mitigation = "",
                     float confidence = 1.0f);

public:
    PESuspiciousTechniqueAnalyzer();
    ~PESuspiciousTechniqueAnalyzer();


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


    void printAnalysis() const;
    void saveAnalysisToFile(const std::string& filename) const;


    const std::vector<SuspiciousTechnique>& getDetectedTechniques() const;
    int getTotalSeverityScore() const;
    bool isSuspicious() const;
    std::string getThreatLevel() const;
};

#endif
