#pragma once
#include "peCommon.h"
#include "outputCapture.h"
const char* GetImageCharacteristics(DWORD_PTR characteristics);
const char* GetSubsystem(WORD subsystem);
const char* GetDataDirectoryName(int directoryNumber);
void DisplayDosHeader(PIMAGE_DOS_HEADER dosHeader);
void DisplayNTHeader(PPE_FILE_INFO fileInfo);
void DisplayFileHeader(const IMAGE_FILE_HEADER* fileHeader);
void DisplayOptionalHeader32(const IMAGE_OPTIONAL_HEADER32* optionalHeader);
void DisplayOptionalHeader64(const IMAGE_OPTIONAL_HEADER64* optionalHeader);
void DisplayDataDirectories(const IMAGE_DATA_DIRECTORY* imageDataDirectory);
