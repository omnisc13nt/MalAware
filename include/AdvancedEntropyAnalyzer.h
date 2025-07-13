#ifndef ADVANCED_ENTROPY_ANALYZER_H
#define ADVANCED_ENTROPY_ANALYZER_H
#include <string>
#include <vector>
#include <map>
#include <cstdint>
class AdvancedEntropyAnalyzer {
public:
    struct EntropyResult {
        double entropy;
        std::string visualization;
        std::string classification;
        bool isPacked;
        bool isCompressed;
        bool isEncrypted;
        double confidence;
    };
    struct SectionEntropyAnalysis {
        std::string sectionName;
        EntropyResult result;
        size_t sectionSize;
        uint32_t virtualAddress;
    };
    struct OverallEntropyReport {
        std::vector<SectionEntropyAnalysis> sections;
        EntropyResult fileOverall;
        std::string packingIndicators;
        std::vector<std::string> suspiciousRegions;
        double riskScore;
    };
    AdvancedEntropyAnalyzer();
    ~AdvancedEntropyAnalyzer();
    double calculateEntropy(const uint8_t* data, size_t size);
    std::string generateEntropyVisualization(double entropy, int maxChars = 20);
    std::string classifyEntropy(double entropy);
    bool detectPacking(const uint8_t* data, size_t size);
    OverallEntropyReport analyzeFile(const std::string& filePath);
    std::vector<double> calculateSlidingEntropy(const uint8_t* data, size_t size, size_t windowSize = 1024);
    std::vector<std::string> detectSuspiciousPatterns(const std::vector<double>& entropyValues);
    double estimateCompressionRatio(const uint8_t* data, size_t size);
private:
    std::map<uint8_t, uint32_t> calculateFrequencies(const uint8_t* data, size_t size);
    double calculateShannonEntropy(const std::map<uint8_t, uint32_t>& frequencies, size_t totalBytes);
    struct PackingIndicators {
        bool highEntropy;
        bool lowImportCount;
        bool suspiciousEntryPoint;
        bool packedSections;
        double confidence;
    };
    PackingIndicators analyzePackingIndicators(const uint8_t* data, size_t size);
    bool checkHighEntropyRegions(const std::vector<double>& entropyValues);
    static constexpr double LOW_ENTROPY_THRESHOLD = 3.0;
    static constexpr double MEDIUM_ENTROPY_THRESHOLD = 6.0;
    static constexpr double HIGH_ENTROPY_THRESHOLD = 7.5;
    static constexpr double PACKING_ENTROPY_THRESHOLD = 7.8;
    static constexpr char ENTROPY_CHAR_FULL = '#';
    static constexpr char ENTROPY_CHAR_HIGH = '=';
    static constexpr char ENTROPY_CHAR_MED = '-';
    static constexpr char ENTROPY_CHAR_LOW = '.';
    static constexpr char ENTROPY_CHAR_EMPTY = ' ';
};
#endif
