#include "../include/JSONOutputManager.h"
#include <fstream>
#include <ctime>
#include <iomanip>

JSONOutputManager::JSONOutputManager() {
    analysisTimestamp_ = getCurrentTimestamp();
}

void JSONOutputManager::addResult(const std::string& analysisType, const std::string& status, 
                                 const std::string& errorMessage) {
    AnalysisResult result;
    result.analysisType = analysisType;
    result.status = status;
    result.errorMessage = errorMessage;
    
    results_[analysisType] = result;
}

void JSONOutputManager::addData(const std::string& analysisType, const std::string& key, 
                               const std::string& value) {
    if (results_.find(analysisType) == results_.end()) {
        addResult(analysisType, "unknown");
    }
    
    results_[analysisType].data[key] = value;
}

void JSONOutputManager::addArrayData(const std::string& analysisType, 
                                    const std::map<std::string, std::string>& data) {
    if (results_.find(analysisType) == results_.end()) {
        addResult(analysisType, "unknown");
    }
    
    results_[analysisType].arrayData.push_back(data);
}

void JSONOutputManager::setFileInfo(const std::string& filename, const std::string& fileSize,
                                   const std::string& fileType, const std::string& architecture) {
    fileInfo_["filename"] = filename;
    fileInfo_["fileSize"] = fileSize;
    fileInfo_["fileType"] = fileType;
    fileInfo_["architecture"] = architecture;
}

std::string JSONOutputManager::generateJSON(bool prettyPrint) const {
    std::stringstream ss;
    
    if (prettyPrint) {
        ss << "{\n";
        ss << "  \"metadata\": " << generateMetadataJSON() << ",\n";
        ss << "  \"fileInfo\": " << generateFileInfoJSON() << ",\n";
        ss << "  \"analysisResults\": " << generateResultsJSON() << "\n";
        ss << "}\n";
    } else {
        ss << "{\"metadata\":" << generateMetadataJSON() << ",";
        ss << "\"fileInfo\":" << generateFileInfoJSON() << ",";
        ss << "\"analysisResults\":" << generateResultsJSON() << "}";
    }
    
    return ss.str();
}

std::string JSONOutputManager::generateXML() const {
    std::stringstream ss;
    
    ss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    ss << "<PEAnalysis>\n";
    ss << "  <Metadata>\n";
    ss << "    <Timestamp>" << escapeXML(analysisTimestamp_) << "</Timestamp>\n";
    ss << "    <Version>1.0</Version>\n";
    ss << "    <Tool>PE File Parser</Tool>\n";
    ss << "  </Metadata>\n";
    
    ss << "  <FileInfo>\n";
    for (const auto& pair : fileInfo_) {
        ss << "    <" << pair.first << ">" << escapeXML(pair.second) << "</" << pair.first << ">\n";
    }
    ss << "  </FileInfo>\n";
    
    ss << "  <AnalysisResults>\n";
    for (const auto& pair : results_) {
        const auto& result = pair.second;
        ss << "    <Analysis type=\"" << escapeXML(result.analysisType) << "\">\n";
        ss << "      <Status>" << escapeXML(result.status) << "</Status>\n";
        if (!result.errorMessage.empty()) {
            ss << "      <Error>" << escapeXML(result.errorMessage) << "</Error>\n";
        }
        
        if (!result.data.empty()) {
            ss << "      <Data>\n";
            for (const auto& dataPair : result.data) {
                ss << "        <" << dataPair.first << ">" << escapeXML(dataPair.second) << "</" << dataPair.first << ">\n";
            }
            ss << "      </Data>\n";
        }
        
        if (!result.arrayData.empty()) {
            ss << "      <ArrayData>\n";
            for (const auto& arrayItem : result.arrayData) {
                ss << "        <Item>\n";
                for (const auto& itemPair : arrayItem) {
                    ss << "          <" << itemPair.first << ">" << escapeXML(itemPair.second) << "</" << itemPair.first << ">\n";
                }
                ss << "        </Item>\n";
            }
            ss << "      </ArrayData>\n";
        }
        
        ss << "    </Analysis>\n";
    }
    ss << "  </AnalysisResults>\n";
    ss << "</PEAnalysis>\n";
    
    return ss.str();
}

std::string JSONOutputManager::generateCSV() const {
    std::stringstream ss;
    
    ss << "Analysis Type,Status,Error Message,Key,Value\n";
    
    for (const auto& pair : results_) {
        const auto& result = pair.second;
        
        if (result.data.empty()) {
            ss << result.analysisType << "," << result.status << "," 
               << result.errorMessage << ",,\n";
        } else {
            for (const auto& dataPair : result.data) {
                ss << result.analysisType << "," << result.status << "," 
                   << result.errorMessage << "," << dataPair.first << "," 
                   << dataPair.second << "\n";
            }
        }
    }
    
    return ss.str();
}

bool JSONOutputManager::saveToFile(const std::string& filename, const std::string& format) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string content;
    if (format == "json") {
        content = generateJSON(true);
    } else if (format == "xml") {
        content = generateXML();
    } else if (format == "csv") {
        content = generateCSV();
    } else {
        return false;
    }
    
    file << content;
    file.close();
    return true;
}

int JSONOutputManager::getSuccessCount() const {
    int count = 0;
    for (const auto& pair : results_) {
        if (pair.second.status == "success") {
            count++;
        }
    }
    return count;
}

int JSONOutputManager::getFailureCount() const {
    int count = 0;
    for (const auto& pair : results_) {
        if (pair.second.status == "error" || pair.second.status == "failed") {
            count++;
        }
    }
    return count;
}

std::vector<std::string> JSONOutputManager::getFailedAnalyses() const {
    std::vector<std::string> failed;
    for (const auto& pair : results_) {
        if (pair.second.status == "error" || pair.second.status == "failed") {
            failed.push_back(pair.first);
        }
    }
    return failed;
}

void JSONOutputManager::clear() {
    results_.clear();
    fileInfo_.clear();
    analysisTimestamp_ = getCurrentTimestamp();
}

std::string JSONOutputManager::escapeJSON(const std::string& str) const {
    std::string escaped;
    for (char c : str) {
        switch (c) {
            case '\"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (c < 32) {
                    escaped += "\\u" + std::to_string(static_cast<unsigned char>(c));
                } else {
                    escaped += c;
                }
                break;
        }
    }
    return escaped;
}

std::string JSONOutputManager::escapeXML(const std::string& str) const {
    std::string escaped;
    for (char c : str) {
        switch (c) {
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            case '&': escaped += "&amp;"; break;
            case '\"': escaped += "&quot;"; break;
            case '\'': escaped += "&apos;"; break;
            default: escaped += c; break;
        }
    }
    return escaped;
}

std::string JSONOutputManager::getCurrentTimestamp() const {
    auto now = std::time(nullptr);
    auto localTime = std::localtime(&now);
    
    std::stringstream ss;
    ss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S UTC");
    return ss.str();
}

std::string JSONOutputManager::formatValue(const std::string& value) const {
    if (value.empty()) return "\"\"";
    
    bool isNumeric = true;
    for (char c : value) {
        if (!std::isdigit(c) && c != '.' && c != '-' && c != '+') {
            isNumeric = false;
            break;
        }
    }
    
    if (isNumeric) {
        return value;
    } else {
        return "\"" + escapeJSON(value) + "\"";
    }
}

std::string JSONOutputManager::generateFileInfoJSON() const {
    std::stringstream ss;
    ss << "{\n";
    
    bool first = true;
    for (const auto& pair : fileInfo_) {
        if (!first) ss << ",\n";
        ss << "    \"" << pair.first << "\": " << formatValue(pair.second);
        first = false;
    }
    
    ss << "\n  }";
    return ss.str();
}

std::string JSONOutputManager::generateResultsJSON() const {
    std::stringstream ss;
    ss << "{\n";
    
    bool first = true;
    for (const auto& pair : results_) {
        if (!first) ss << ",\n";
        
        const auto& result = pair.second;
        ss << "    \"" << result.analysisType << "\": {\n";
        ss << "      \"status\": \"" << result.status << "\"";
        
        if (!result.errorMessage.empty()) {
            ss << ",\n      \"error\": \"" << escapeJSON(result.errorMessage) << "\"";
        }
        
        if (!result.data.empty()) {
            ss << ",\n      \"data\": {\n";
            bool firstData = true;
            for (const auto& dataPair : result.data) {
                if (!firstData) ss << ",\n";
                ss << "        \"" << dataPair.first << "\": " << formatValue(dataPair.second);
                firstData = false;
            }
            ss << "\n      }";
        }
        
        if (!result.arrayData.empty()) {
            ss << ",\n      \"arrayData\": [\n";
            bool firstArray = true;
            for (const auto& arrayItem : result.arrayData) {
                if (!firstArray) ss << ",\n";
                ss << "        {\n";
                bool firstItem = true;
                for (const auto& itemPair : arrayItem) {
                    if (!firstItem) ss << ",\n";
                    ss << "          \"" << itemPair.first << "\": " << formatValue(itemPair.second);
                    firstItem = false;
                }
                ss << "\n        }";
                firstArray = false;
            }
            ss << "\n      ]";
        }
        
        ss << "\n    }";
        first = false;
    }
    
    ss << "\n  }";
    return ss.str();
}

std::string JSONOutputManager::generateMetadataJSON() const {
    std::stringstream ss;
    ss << "{\n";
    ss << "    \"timestamp\": \"" << analysisTimestamp_ << "\",\n";
    ss << "    \"version\": \"1.0\",\n";
    ss << "    \"tool\": \"PE File Parser\",\n";
    ss << "    \"successCount\": " << getSuccessCount() << ",\n";
    ss << "    \"failureCount\": " << getFailureCount() << "\n";
    ss << "  }";
    return ss.str();
}
