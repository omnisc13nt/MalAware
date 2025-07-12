
#pragma once

#include "peCommon.h"
#include <string>

/**
 * Retrieve and display the protection of the section.
 * @param dCharacteristics : characteristics of the section.
 * @return : the description of the protection.
 */
std::string GetSectionProtection(DWORD_PTR dCharacteristics);

/**
 * Function to retrieve sections from the PE file and get the section which contains imports.
 * @param pImageSectionHeader : section header of the PE file.
 * @param nNumberOfSections : number of section in the PE file.
 * @param dImportAddress : address of import found into DataDirectory 1.
 * @return : section which contains imports.
 */
PIMAGE_SECTION_HEADER GetSections(PIMAGE_SECTION_HEADER pImageSectionHeader, 
                                  int nNumberOfSections, 
                                  DWORD_PTR dImportAddress);

/**
 * Retrieve the section which contains exports.
 * @param pImageSectionHeader : section header of the PE file.
 * @param nNumberOfSections : number of sections.
 * @param dExportAddress : export address get from the DataDirectory 0.
 * @return : the section which contains exports.
 */
PIMAGE_SECTION_HEADER GetExportSection(PIMAGE_SECTION_HEADER pImageSectionHeader, 
                                       int nNumberOfSections, 
                                       DWORD_PTR dExportAddress);

/**
 * Display information about all sections in the PE file.
 * @param pImageSectionHeader : section header of the PE file.
 * @param nNumberOfSections : number of sections in the PE file.
 */
void DisplaySections(PIMAGE_SECTION_HEADER pImageSectionHeader, int nNumberOfSections);
