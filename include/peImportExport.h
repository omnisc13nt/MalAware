#pragma once

#include "peCommon.h"
#include "outputCapture.h"

DWORD_PTR RvaToFileOffset(DWORD_PTR rva, PIMAGE_SECTION_HEADER pSectionHeader, int nNumberOfSections);

void GetImports32(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor, 
                  DWORD_PTR dRawOffset, 
                  PIMAGE_SECTION_HEADER pImageImportSection);

void GetImports64(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor, 
                  DWORD_PTR dRawOffset, 
                  PIMAGE_SECTION_HEADER pImageImportSection);

void GetExports(PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, 
                DWORD_PTR dRawOffset, 
                PIMAGE_SECTION_HEADER pImageExportSection);

int ParseImports(PPE_FILE_INFO pFileInfo);

int ParseExports(PPE_FILE_INFO pFileInfo);
