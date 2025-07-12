#pragma once

#include "pe_common.h"

/**
 * Main PE parsing function for 32-bit PE files.
 * @param pFileInfo : pointer to PE_FILE_INFO structure.
 * @return : PE_SUCCESS if successful, error code otherwise.
 */
int ParsePE32(PPE_FILE_INFO pFileInfo);

/**
 * Main PE parsing function for 64-bit PE files.
 * @param pFileInfo : pointer to PE_FILE_INFO structure.
 * @return : PE_SUCCESS if successful, error code otherwise.
 */
int ParsePE64(PPE_FILE_INFO pFileInfo);

/**
 * Main PE parsing function that determines architecture and calls appropriate parser.
 * @param pFileInfo : pointer to PE_FILE_INFO structure.
 * @return : PE_SUCCESS if successful, error code otherwise.
 */
int ParsePEFile(PPE_FILE_INFO pFileInfo);
