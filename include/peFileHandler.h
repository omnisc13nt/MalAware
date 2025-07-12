#pragma once

#include "peCommon.h"
#include "outputCapture.h"

/**
 * Function to retrieve the PE file content.
 * @param lpFilePath : path of the PE file.
 * @param pFileInfo : pointer to PE_FILE_INFO structure to be filled.
 * @return : PE_SUCCESS if successful, error code otherwise.
 */
int LoadPEFile(const char* lpFilePath, PPE_FILE_INFO pFileInfo);

/**
 * Function to clean up allocated resources.
 * @param pFileInfo : pointer to PE_FILE_INFO structure.
 */
void CleanupPEFile(PPE_FILE_INFO pFileInfo);

/**
 * Function to validate PE file structure.
 * @param pFileInfo : pointer to PE_FILE_INFO structure.
 * @return : PE_SUCCESS if valid, error code otherwise.
 */
int ValidatePEFile(PPE_FILE_INFO pFileInfo);
