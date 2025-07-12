#pragma once

#include "pe_common.h"

/**
 * Function to identify the PE file characteristics.
 * @param dCharacteristics : characteristics in the file header section.
 * @return : the description of the PE file characteristics.
 */
const char* GetImageCharacteristics(DWORD_PTR dCharacteristics);

/**
 * Function to identify the PE file subsystem.
 * @param wSubsystem : subsystem in the optional header.
 * @return : the description of the PE file subsystem.
 */
const char* GetSubsystem(WORD wSubsystem);

/**
 * Function to identify the DataDirectory.
 * @param nDirectoryNumber : index of the DataDirectory.
 * @return : the description of the DataDirectory.
 */
const char* GetDataDirectoryName(int nDirectoryNumber);

/**
 * Function to display DOS header information.
 * @param pDosHeader : pointer to DOS header.
 */
void DisplayDosHeader(PIMAGE_DOS_HEADER pDosHeader);

/**
 * Function to display NT header information.
 * @param pFileInfo : pointer to PE_FILE_INFO structure.
 */
void DisplayNTHeader(PPE_FILE_INFO pFileInfo);

/**
 * Function to display File header information.
 * @param pFileHeader : pointer to File header.
 */
void DisplayFileHeader(const IMAGE_FILE_HEADER* pFileHeader);

/**
 * Function to display Optional header information for 32-bit PE.
 * @param pOptionalHeader : pointer to Optional header.
 */
void DisplayOptionalHeader32(const IMAGE_OPTIONAL_HEADER32* pOptionalHeader);

/**
 * Function to display Optional header information for 64-bit PE.
 * @param pOptionalHeader : pointer to Optional header.
 */
void DisplayOptionalHeader64(const IMAGE_OPTIONAL_HEADER64* pOptionalHeader);

/**
 * Retrieve and display the DataDirectory informations.
 * @param pImageDataDirectory : DataDirectory array of the optional header.
 */
void DisplayDataDirectories(const IMAGE_DATA_DIRECTORY* pImageDataDirectory);
