#pragma once
#include "peCommon.h"
#include "outputCapture.h"
#include <string>
#include <vector>
class PEParser {
public:
    explicit PEParser(const std::string& filePath);
    ~PEParser();
    bool isValid() const;
    bool is64Bit() const;
    std::string getErrorMessage() const;
    void printSummary() const;
    void printHeaders() const;
    void printSections() const;
    void printImports() const;
    void printExports() const;
    void printDigitalSignature() const;
    void printExceptionData() const;
    void printDebugInfo() const;
    void printTLSCallbacks() const;
    void printDelayImports() const;
    void printBoundImports() const;
    void printDotNetMetadata() const;
    void printIATReconstruction() const;
    void printDisassembly() const;
    void printDependencies() const;
private:
    bool loadFile(const std::string& filePath);
    bool validatePE();
    void cleanup();
    HANDLE fileContent_;
    DWORD fileSize_;
    PIMAGE_DOS_HEADER dosHeader_;
    PIMAGE_NT_HEADERS ntHeader_;
    bool is64Bit_;
    std::string errorMessage_;
};
