#pragma once

#include "peCommon.h"
#include "outputCapture.h"

int ParsePE32(PPE_FILE_INFO pFileInfo);

int ParsePE64(PPE_FILE_INFO pFileInfo);

int ParsePEFile(PPE_FILE_INFO pFileInfo);
