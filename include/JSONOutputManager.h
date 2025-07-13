#pragma once

#include "peCommon.h"
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <memory>

class JSONOutputManager {
public:
    struct AnalysisResult {
        std::string analysisType;
        std::string status;
        std::string errorMessage;
        std::map<std::string, std::string> data;
        std::vector<std::map<std::string, std::string>> arrayData;
    };
    
    JSONOutputManager();
    ~JSONOutputManager() = default;
    
    void addResult(const std::string& analysisType, const std::string& status, 
                   const std::string& errorMessage = "");
    void addData(const std::string& analysisType, const std::string& key, 
                 const std::string& value);
    void addArrayData(const std::string& analysisType, 
                      const std::map<std::string, std::string>& data);
    
    void setFileInfo(const std::string& filename, const std::string& fileSize,
                     const std::string& fileType, const std::string& architecture);
    
    std::string generateJSON(bool prettyPrint = true) const;
    std::string generateXML() const;
    std::string generateCSV() const;
    
    bool saveToFile(const std::string& filename, const std::string& format = "json") const;
    
    int getSuccessCount() const;
    int getFailureCount() const;
    std::vector<std::string> getFailedAnalyses() const;
    
    void clear();

private:
    std::map<std::string, AnalysisResult> results_;
    std::map<std::string, std::string> fileInfo_;
    std::string analysisTimestamp_;
    
    std::string escapeJSON(const std::string& str) const;
    std::string escapeXML(const std::string& str) const;
    std::string getCurrentTimestamp() const;
    std::string formatValue(const std::string& value) const;
    
    std::string generateFileInfoJSON() const;
    std::string generateResultsJSON() const;
    std::string generateMetadataJSON() const;
};
