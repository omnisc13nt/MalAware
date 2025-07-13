#pragma once
#include "peCommon.h"
#include "outputCapture.h"
#include <string>
std::string GetSectionProtection(DWORD_PTR dCharacteristics);
PIMAGE_SECTION_HEADER GetSections(PIMAGE_SECTION_HEADER pImageSectionHeader, 
                                  int nNumberOfSections, 
                                  DWORD_PTR dImportAddress);
PIMAGE_SECTION_HEADER GetExportSection(PIMAGE_SECTION_HEADER pImageSectionHeader, 
                                       int nNumberOfSections, 
                                       DWORD_PTR dExportAddress);
void DisplaySections(PIMAGE_SECTION_HEADER pImageSectionHeader, int nNumberOfSections);
