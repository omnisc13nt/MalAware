#ifndef ENHANCED_OUTPUT_MANAGER_H
#define ENHANCED_OUTPUT_MANAGER_H
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <memory>
class EnhancedOutputManager {
public:
    enum class OutputFormat {
        TEXT,
        XML,
        CSV,
        SUMMARY
    };
    struct AnalysisData {
        std::string fileName;
        std::string filePath;
        size_t fileSize;
        std::string architecture;
        std::string md5;
        std::string sha1;
        std::string sha256;
        std::string imphash;
        std::string ssdeep;
        std::string tlsh;
        std::string vhash;
        uint32_t compilationTime;
        uint16_t sectionCount;
        uint32_t entryPoint;
        std::string subsystem;
        bool aslrEnabled;
        bool depEnabled;
        bool sehEnabled;
        bool cfgEnabled;
        bool nxCompatible;
        uint32_t importCount;
        uint32_t dllCount;
        uint32_t corruptedImports;
        std::vector<std::string> importedDlls;
        double overallEntropy;
        std::vector<std::pair<std::string, double>> sectionEntropies;
        bool packingDetected;
        uint32_t riskScore;
        std::string classification;
        std::vector<std::string> threatIndicators;
        std::string recommendation;
        double analysisTime;
        size_t memoryUsage;
        std::string analysisTimestamp;
    };
    EnhancedOutputManager();
    ~EnhancedOutputManager();
    void setOutputFormat(OutputFormat format);
    void setOutputFile(const std::string& filePath);
    bool generateOutput(const AnalysisData& data);
    std::string generateXML(const AnalysisData& data);
    std::string generateCSV(const AnalysisData& data);
    std::string generateSummary(const AnalysisData& data);
    std::string generateText(const AnalysisData& data);
    std::string getCSVHeader();
    bool isFormatSupported(OutputFormat format);
private:
    OutputFormat currentFormat;
    std::string outputFilePath;
    std::string xmlEscape(const std::string& str);
    std::string xmlElement(const std::string& name, const std::string& value);
    std::string xmlElement(const std::string& name, bool value);
    std::string xmlElement(const std::string& name, uint32_t value);
    std::string xmlElement(const std::string& name, double value);
    std::string csvEscape(const std::string& str);
    std::string formatTimestamp(uint32_t timestamp);
    std::string formatFileSize(size_t size);
    std::string getCurrentTimestamp();
};
#endif
