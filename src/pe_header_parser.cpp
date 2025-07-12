#include "../include/pe_header_parser.h"

const char* GetImageCharacteristics(DWORD_PTR dCharacteristics)
{
    if (dCharacteristics & IMAGE_FILE_DLL)
        return "(DLL)";

    if (dCharacteristics & IMAGE_FILE_SYSTEM)
        return "(DRIVER)";

    if (dCharacteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        return "(EXE)";

    return "(UNKNOWN)";
}

const char* GetSubsystem(WORD wSubsystem)
{
    switch (wSubsystem)
    {
        case 1:
            return "(NATIVE / DRIVER)";
        case 2:
            return "(GUI APP)";
        case 3:
            return "(CONSOLE APP)";
        default:
            return "(UNKNOWN)";
    }
}

const char* GetDataDirectoryName(int nDirectoryNumber)
{
    switch (nDirectoryNumber)
    {
        case 0:
            return "Export Table";
        case 1:
            return "Import Table";
        case 2:
            return "Resource Table";
        case 3:
            return "Exception Entry";
        case 4:
            return "Security Entry";
        case 5:
            return "Relocation Table";
        case 6:
            return "Debug Entry";
        case 7:
            return "Copyright Entry";
        case 8:
            return "Global PTR Entry";
        case 9:
            return "TLS Entry";
        case 10:
            return "Configuration Entry";
        case 11:
            return "Bound Import Entry";
        case 12:
            return "IAT";
        case 13:
            return "Delay Import Descriptor";
        case 14:
            return "COM Descriptor";
        default:
            return "Unknown";
    }
}

void DisplayDosHeader(PIMAGE_DOS_HEADER pDosHeader)
{
    printf("\n[+] DOS HEADER\n");
    printf("\te_magic : 0x%X\n", (unsigned int)pDosHeader->e_magic);
    printf("\te_cblp : 0x%X\n", (unsigned int)pDosHeader->e_cblp);
    printf("\te_cp : 0x%X\n", (unsigned int)pDosHeader->e_cp);
    printf("\te_crlc : 0x%X\n", (unsigned int)pDosHeader->e_crlc);
    printf("\te_cparhdr : 0x%X\n", (unsigned int)pDosHeader->e_cparhdr);
    printf("\te_minalloc : 0x%X\n", (unsigned int)pDosHeader->e_minalloc);
    printf("\te_maxalloc : 0x%X\n", (unsigned int)pDosHeader->e_maxalloc);
    printf("\te_ss : 0x%X\n", (unsigned int)pDosHeader->e_ss);
    printf("\te_sp : 0x%X\n", (unsigned int)pDosHeader->e_sp);
    printf("\te_csum : 0x%X\n", (unsigned int)pDosHeader->e_csum);
    printf("\te_ip : 0x%X\n", (unsigned int)pDosHeader->e_ip);
    printf("\te_cs : 0x%X\n", (unsigned int)pDosHeader->e_cs);
    printf("\te_lfarlc : 0x%X\n", (unsigned int)pDosHeader->e_lfarlc);
    printf("\te_ovno : 0x%X\n", (unsigned int)pDosHeader->e_ovno);
    printf("\te_oemid : 0x%X\n", (unsigned int)pDosHeader->e_oemid);
    printf("\te_oeminfo : 0x%X\n", (unsigned int)pDosHeader->e_oeminfo);
    printf("\te_lfanew : 0x%X\n", (unsigned int)pDosHeader->e_lfanew);
}

void DisplayNTHeader(PPE_FILE_INFO pFileInfo)
{
    printf("\n[+] NT HEADER\n");
    printf("\tSignature : 0x%X\n", (unsigned int)pFileInfo->pNtHeader->Signature);
}

void DisplayFileHeader(const IMAGE_FILE_HEADER* pFileHeader)
{
    printf("\n[+] FILE HEADER\n");
    printf("\tMachine : 0x%X\n", (unsigned int)pFileHeader->Machine);
    printf("\tNumberOfSections : 0x%X\n", (unsigned int)pFileHeader->NumberOfSections);
    printf("\tTimeDateStamp : 0x%X\n", (unsigned int)pFileHeader->TimeDateStamp);
    printf("\tPointerToSymbolTable : 0x%X\n", (unsigned int)pFileHeader->PointerToSymbolTable);
    printf("\tNumberOfSymbols : 0x%X\n", (unsigned int)pFileHeader->NumberOfSymbols);
    printf("\tSizeOfOptionalHeader : 0x%X\n", (unsigned int)pFileHeader->SizeOfOptionalHeader);
    printf("\tCharacteristics : 0x%X %s\n", (unsigned int)pFileHeader->Characteristics, GetImageCharacteristics(pFileHeader->Characteristics));
}

void DisplayOptionalHeader32(const IMAGE_OPTIONAL_HEADER32* pOptionalHeader)
{
    printf("\n[+] OPTIONAL HEADER\n");
    printf("\tMagic : 0x%X\n", (unsigned int)pOptionalHeader->Magic);
    printf("\tMajorLinkerVersion : 0x%X\n", (unsigned int)pOptionalHeader->MajorLinkerVersion);
    printf("\tMinorLinkerVersion : 0x%X\n", (unsigned int)pOptionalHeader->MinorLinkerVersion);
    printf("\tSizeOfCode : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfCode);
    printf("\tSizeOfInitializedData : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfInitializedData);
    printf("\tSizeOfUninitializedData : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfUninitializedData);
    printf("\tAddressOfEntryPoint : 0x%X\n", (unsigned int)pOptionalHeader->AddressOfEntryPoint);
    printf("\tBaseOfCode : 0x%X\n", (unsigned int)pOptionalHeader->BaseOfCode);
    printf("\tBaseOfData : 0x%X\n", (unsigned int)pOptionalHeader->BaseOfData);
    printf("\tImageBase : 0x%X\n", (unsigned int)pOptionalHeader->ImageBase);
    printf("\tSectionAlignment : 0x%X\n", (unsigned int)pOptionalHeader->SectionAlignment);
    printf("\tFileAlignment : 0x%X\n", (unsigned int)pOptionalHeader->FileAlignment);
    printf("\tMajorOperatingSystemVersion : 0x%X\n", (unsigned int)pOptionalHeader->MajorOperatingSystemVersion);
    printf("\tMinorOperatingSystemVersion : 0x%X\n", (unsigned int)pOptionalHeader->MinorOperatingSystemVersion);
    printf("\tMajorImageVersion : 0x%X\n", (unsigned int)pOptionalHeader->MajorImageVersion);
    printf("\tMinorImageVersion : 0x%X\n", (unsigned int)pOptionalHeader->MinorImageVersion);
    printf("\tMajorSubsystemVersion : 0x%X\n", (unsigned int)pOptionalHeader->MajorSubsystemVersion);
    printf("\tMinorSubsystemVersion : 0x%X\n", (unsigned int)pOptionalHeader->MinorSubsystemVersion);
    printf("\tWin32VersionValue : 0x%X\n", (unsigned int)pOptionalHeader->Win32VersionValue);
    printf("\tSizeOfImage : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfImage);
    printf("\tSizeOfHeaders : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfHeaders);
    printf("\tCheckSum : 0x%X\n", (unsigned int)pOptionalHeader->CheckSum);
    printf("\tSubsystem : 0x%X %s\n", (unsigned int)pOptionalHeader->Subsystem, GetSubsystem(pOptionalHeader->Subsystem));
    printf("\tDllCharacteristics : 0x%X\n", (unsigned int)pOptionalHeader->DllCharacteristics);
    printf("\tSizeOfStackReserve : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfStackReserve);
    printf("\tSizeOfStackCommit : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfStackCommit);
    printf("\tSizeOfHeapReserve : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfHeapReserve);
    printf("\tSizeOfHeapCommit : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfHeapCommit);
    printf("\tLoaderFlags : 0x%X\n", (unsigned int)pOptionalHeader->LoaderFlags);
    printf("\tNumberOfRvaAndSizes : 0x%X\n", (unsigned int)pOptionalHeader->NumberOfRvaAndSizes);
    
    DisplayDataDirectories(pOptionalHeader->DataDirectory);
}

void DisplayOptionalHeader64(const IMAGE_OPTIONAL_HEADER64* pOptionalHeader)
{
    printf("\n[+] OPTIONAL HEADER\n");
    printf("\tMagic : 0x%X\n", (unsigned int)pOptionalHeader->Magic);
    printf("\tMajorLinkerVersion : 0x%X\n", (unsigned int)pOptionalHeader->MajorLinkerVersion);
    printf("\tMinorLinkerVersion : 0x%X\n", (unsigned int)pOptionalHeader->MinorLinkerVersion);
    printf("\tSizeOfCode : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfCode);
    printf("\tSizeOfInitializedData : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfInitializedData);
    printf("\tSizeOfUninitializedData : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfUninitializedData);
    printf("\tAddressOfEntryPoint : 0x%X\n", (unsigned int)pOptionalHeader->AddressOfEntryPoint);
    printf("\tBaseOfCode : 0x%X\n", (unsigned int)pOptionalHeader->BaseOfCode);
    printf("\tImageBase : 0x%llX\n", (unsigned long long)pOptionalHeader->ImageBase);
    printf("\tSectionAlignment : 0x%X\n", (unsigned int)pOptionalHeader->SectionAlignment);
    printf("\tFileAlignment : 0x%X\n", (unsigned int)pOptionalHeader->FileAlignment);
    printf("\tMajorOperatingSystemVersion : 0x%X\n", (unsigned int)pOptionalHeader->MajorOperatingSystemVersion);
    printf("\tMinorOperatingSystemVersion : 0x%X\n", (unsigned int)pOptionalHeader->MinorOperatingSystemVersion);
    printf("\tMajorImageVersion : 0x%X\n", (unsigned int)pOptionalHeader->MajorImageVersion);
    printf("\tMinorImageVersion : 0x%X\n", (unsigned int)pOptionalHeader->MinorImageVersion);
    printf("\tMajorSubsystemVersion : 0x%X\n", (unsigned int)pOptionalHeader->MajorSubsystemVersion);
    printf("\tMinorSubsystemVersion : 0x%X\n", (unsigned int)pOptionalHeader->MinorSubsystemVersion);
    printf("\tWin32VersionValue : 0x%X\n", (unsigned int)pOptionalHeader->Win32VersionValue);
    printf("\tSizeOfImage : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfImage);
    printf("\tSizeOfHeaders : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfHeaders);
    printf("\tCheckSum : 0x%X\n", (unsigned int)pOptionalHeader->CheckSum);
    printf("\tSubsystem : 0x%X %s\n", (unsigned int)pOptionalHeader->Subsystem, GetSubsystem(pOptionalHeader->Subsystem));
    printf("\tDllCharacteristics : 0x%X\n", (unsigned int)pOptionalHeader->DllCharacteristics);
    printf("\tSizeOfStackReserve : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfStackReserve);
    printf("\tSizeOfStackCommit : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfStackCommit);
    printf("\tSizeOfHeapReserve : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfHeapReserve);
    printf("\tSizeOfHeapCommit : 0x%X\n", (unsigned int)pOptionalHeader->SizeOfHeapCommit);
    printf("\tLoaderFlags : 0x%X\n", (unsigned int)pOptionalHeader->LoaderFlags);
    printf("\tNumberOfRvaAndSizes : 0x%X\n", (unsigned int)pOptionalHeader->NumberOfRvaAndSizes);
    
    DisplayDataDirectories(pOptionalHeader->DataDirectory);
}

void DisplayDataDirectories(const IMAGE_DATA_DIRECTORY* pImageDataDirectory)
{
    printf("\n[+] DATA DIRECTORIES\n");
    
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i, ++pImageDataDirectory)
    {
        if (pImageDataDirectory->VirtualAddress == 0)
            continue;

        printf("\tDataDirectory (%s) VirtualAddress : 0x%X\n", GetDataDirectoryName(i), (unsigned int)pImageDataDirectory->VirtualAddress);
        printf("\tDataDirectory (%s) Size : 0x%X\n\n", GetDataDirectoryName(i), (unsigned int)pImageDataDirectory->Size);
    }
}
