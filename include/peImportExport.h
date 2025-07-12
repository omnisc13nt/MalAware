#pragma once

#include "peCommon.h"

/**
 * Retrieve and display dll and functions imported (for x86 PE file).
 * @param pImageImportDescriptor : import descriptor of the PE file.
 * @param dRawOffset : address of raw data of the import section.
 * @param pImageImportSection : section which contains imports.
 */
void GetImports32(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor, 
                  DWORD_PTR dRawOffset, 
                  PIMAGE_SECTION_HEADER pImageImportSection);

/**
 * Retrieve and display dll and functions imported (for x64 PE file).
 * @param pImageImportDescriptor : import descriptor of the PE file.
 * @param dRawOffset : address of raw data of the import section.
 * @param pImageImportSection : section which contains imports.
 */
void GetImports64(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor, 
                  DWORD_PTR dRawOffset, 
                  PIMAGE_SECTION_HEADER pImageImportSection);

/**
 * Retrieve and display exported functions.
 * @param pImageExportDirectory : export directory which contains every informations on exported functions.
 * @param dRawOffset : address of raw data of the section which contains exports.
 * @param pImageExportSection : section which contains exports.
 */
void GetExports(PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, 
                DWORD_PTR dRawOffset, 
                PIMAGE_SECTION_HEADER pImageExportSection);

/**
 * Parse and display import table for PE file.
 * @param pFileInfo : pointer to PE_FILE_INFO structure.
 * @return : PE_SUCCESS if successful, error code otherwise.
 */
int ParseImports(PPE_FILE_INFO pFileInfo);

/**
 * Parse and display export table for PE file.
 * @param pFileInfo : pointer to PE_FILE_INFO structure.
 * @return : PE_SUCCESS if successful, error code otherwise.
 */
int ParseExports(PPE_FILE_INFO pFileInfo);
