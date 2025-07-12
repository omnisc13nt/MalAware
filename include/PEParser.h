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
    // Future: void printResources() const;
    // Future: void printRelocations() const;

    // Digital signature (Authenticode) parsing
    void printDigitalSignature() const;

    // Exception handling data parsing
    void printExceptionData() const;

    // Debug information parsing
    void printDebugInfo() const;

    // TLS callbacks parsing
    void printTLSCallbacks() const;

    // Delay-loaded imports parsing
    void printDelayImports() const;

    // Bound imports parsing
    void printBoundImports() const;

    // .NET metadata parsing
    void printDotNetMetadata() const;

    // IAT reconstruction
    void printIATReconstruction() const;

    // Disassembly (basic)
    void printDisassembly() const;

    // Dependency scanner
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
