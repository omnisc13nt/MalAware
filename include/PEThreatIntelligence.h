#pragma once
#include "peCommon.h"
#include <string>
#include <vector>
#include <map>

enum class IntelligenceSource {
    VIRUSTOTAL,
    HYBRID_ANALYSIS,
    MALWARE_BAZAAR,
    INTEZER,
    JOE_SANDBOX,
    METADEFENDER,
    LOCAL_DATABASE
};

enum class DetectionLevel {
    CLEAN = 0,
    SUSPICIOUS = 1,
    MALICIOUS = 2,
    UNKNOWN = 3
};

struct ThreatDetection {
    std::string engineName;
    DetectionLevel level;
    std::string malwareName;
    std::string category;
    std::string version;
};

struct ThreatIntelligence {
    std::string fileHash;
    IntelligenceSource source;
    std::vector<ThreatDetection> detections;
    std::string reportUrl;
    std::string firstSeen;
    std::string lastSeen;
    int reputationScore;
    std::map<std::string, std::string> metadata;
};

class PEThreatIntelligence {
private:
    PPE_FILE_INFO pFileInfo;
    std::vector<ThreatIntelligence> intelligenceReports;
    std::map<std::string, std::string> apiKeys;
    
public:
    PEThreatIntelligence(PPE_FILE_INFO fileInfo);
    
    void SetApiKey(IntelligenceSource source, const std::string& key);
    void LoadConfiguration(const std::string& configPath);
    
    bool QueryVirusTotal(const std::string& hash);
    bool QueryHybridAnalysis(const std::string& hash);
    bool QueryMalwareBazaar(const std::string& hash);
    bool QueryIntezer(const std::string& hash);
    bool QueryLocalDatabase(const std::string& hash);
    
    void QueryAllSources();
    void QueryAvailableSources();
    
    DetectionLevel GetOverallThreatLevel();
    std::string GetConsensusVerdict();
    std::vector<std::string> GetMalwareFamilies();
    int GetDetectionRate();
    
    const std::vector<ThreatIntelligence>& GetIntelligenceReports() const;
    ThreatIntelligence GetBestReport() const;
    
    void PrintThreatSummary() const;
    std::string GetThreatReport() const;
    void ExportToJson(const std::string& filePath) const;
    
    static std::string DetectionLevelToString(DetectionLevel level);
    static std::string IntelligenceSourceToString(IntelligenceSource source);

private:
    std::string MakeHttpRequest(const std::string& url, const std::map<std::string, std::string>& headers = {});
    std::string GetFileHash(const std::string& algorithm = "sha256");
    ThreatIntelligence ParseVirusTotalResponse(const std::string& response);
    ThreatIntelligence ParseHybridAnalysisResponse(const std::string& response);
    ThreatIntelligence ParseMalwareBazaarResponse(const std::string& response);
    
    bool IsValidApiKey(IntelligenceSource source, const std::string& key);
    void AddIntelligenceReport(const ThreatIntelligence& report);
};
