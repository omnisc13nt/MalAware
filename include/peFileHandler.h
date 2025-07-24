#pragma once
#include "peCommon.h"
#include "outputCapture.h"
int LoadPEFile(const char* filePath, PPE_FILE_INFO fileInfo);
void CleanupPEFile(PPE_FILE_INFO fileInfo);
int ValidatePEFile(PPE_FILE_INFO fileInfo);
