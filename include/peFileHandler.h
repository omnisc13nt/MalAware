#pragma once
#include "peCommon.h"
#include "outputCapture.h"
int LoadPEFile(const char* lpFilePath, PPE_FILE_INFO pFileInfo);
void CleanupPEFile(PPE_FILE_INFO pFileInfo);
int ValidatePEFile(PPE_FILE_INFO pFileInfo);
