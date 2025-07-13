#pragma once
#include "peCommon.h"
#include "outputCapture.h"
const char* GetImageCharacteristics(DWORD_PTR dCharacteristics);
const char* GetSubsystem(WORD wSubsystem);
const char* GetDataDirectoryName(int nDirectoryNumber);
void DisplayDosHeader(PIMAGE_DOS_HEADER pDosHeader);
void DisplayNTHeader(PPE_FILE_INFO pFileInfo);
void DisplayFileHeader(const IMAGE_FILE_HEADER* pFileHeader);
void DisplayOptionalHeader32(const IMAGE_OPTIONAL_HEADER32* pOptionalHeader);
void DisplayOptionalHeader64(const IMAGE_OPTIONAL_HEADER64* pOptionalHeader);
void DisplayDataDirectories(const IMAGE_DATA_DIRECTORY* pImageDataDirectory);
