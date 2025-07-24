#include "../include/peHeaderParser.h"
const char* GetImageCharacteristics(DWORD_PTR characteristics)
{
    if (characteristics & IMAGE_FILE_DLL)
        return "(DLL)";
    if (characteristics & IMAGE_FILE_SYSTEM)
        return "(DRIVER)";
    if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        return "(EXE)";
    return "(UNKNOWN)";
}
const char* GetSubsystem(WORD subsystem)
{
    switch (subsystem)
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
const char* GetDataDirectoryName(int directoryNumber)
{
    switch (directoryNumber)
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
void DisplayDosHeader(PIMAGE_DOS_HEADER dosHeader)
{
    printf("\n[+] DOS HEADER\n");
    printf("\te_magic : 0x%X\n", (unsigned int)dosHeader->e_magic);
    printf("\te_cblp : 0x%X\n", (unsigned int)dosHeader->e_cblp);
    printf("\te_cp : 0x%X\n", (unsigned int)dosHeader->e_cp);
    printf("\te_crlc : 0x%X\n", (unsigned int)dosHeader->e_crlc);
    printf("\te_cparhdr : 0x%X\n", (unsigned int)dosHeader->e_cparhdr);
    printf("\te_minalloc : 0x%X\n", (unsigned int)dosHeader->e_minalloc);
    printf("\te_maxalloc : 0x%X\n", (unsigned int)dosHeader->e_maxalloc);
    printf("\te_ss : 0x%X\n", (unsigned int)dosHeader->e_ss);
    printf("\te_sp : 0x%X\n", (unsigned int)dosHeader->e_sp);
    printf("\te_csum : 0x%X\n", (unsigned int)dosHeader->e_csum);
    printf("\te_ip : 0x%X\n", (unsigned int)dosHeader->e_ip);
    printf("\te_cs : 0x%X\n", (unsigned int)dosHeader->e_cs);
    printf("\te_lfarlc : 0x%X\n", (unsigned int)dosHeader->e_lfarlc);
    printf("\te_ovno : 0x%X\n", (unsigned int)dosHeader->e_ovno);
    printf("\te_oemid : 0x%X\n", (unsigned int)dosHeader->e_oemid);
    printf("\te_oeminfo : 0x%X\n", (unsigned int)dosHeader->e_oeminfo);
    printf("\te_lfanew : 0x%X\n", (unsigned int)dosHeader->e_lfanew);
}
void DisplayNTHeader(PPE_FILE_INFO fileInfo)
{
    printf("\n[+] NT HEADER\n");
    printf("\tSignature : 0x%X\n", (unsigned int)fileInfo->ntHeader->Signature);
}
void DisplayFileHeader(const IMAGE_FILE_HEADER* fileHeader)
{
    printf("\n[+] FILE HEADER\n");
    printf("\tMachine : 0x%X\n", (unsigned int)fileHeader->Machine);
    printf("\tNumberOfSections : 0x%X\n", (unsigned int)fileHeader->NumberOfSections);
    printf("\tTimeDateStamp : 0x%X\n", (unsigned int)fileHeader->TimeDateStamp);
    printf("\tPointerToSymbolTable : 0x%X\n", (unsigned int)fileHeader->PointerToSymbolTable);
    printf("\tNumberOfSymbols : 0x%X\n", (unsigned int)fileHeader->NumberOfSymbols);
    printf("\tSizeOfOptionalHeader : 0x%X\n", (unsigned int)fileHeader->SizeOfOptionalHeader);
    printf("\tCharacteristics : 0x%X %s\n", (unsigned int)fileHeader->Characteristics, GetImageCharacteristics(fileHeader->Characteristics));
}
void DisplayOptionalHeader32(const IMAGE_OPTIONAL_HEADER32* optionalHeader)
{
    printf("\n[+] OPTIONAL HEADER\n");
    printf("\tMagic : 0x%X\n", (unsigned int)optionalHeader->Magic);
    printf("\tMajorLinkerVersion : 0x%X\n", (unsigned int)optionalHeader->MajorLinkerVersion);
    printf("\tMinorLinkerVersion : 0x%X\n", (unsigned int)optionalHeader->MinorLinkerVersion);
    printf("\tSizeOfCode : 0x%X\n", (unsigned int)optionalHeader->SizeOfCode);
    printf("\tSizeOfInitializedData : 0x%X\n", (unsigned int)optionalHeader->SizeOfInitializedData);
    printf("\tSizeOfUninitializedData : 0x%X\n", (unsigned int)optionalHeader->SizeOfUninitializedData);
    printf("\tAddressOfEntryPoint : 0x%X\n", (unsigned int)optionalHeader->AddressOfEntryPoint);
    printf("\tBaseOfCode : 0x%X\n", (unsigned int)optionalHeader->BaseOfCode);
    printf("\tBaseOfData : 0x%X\n", (unsigned int)optionalHeader->BaseOfData);
    printf("\tImageBase : 0x%X\n", (unsigned int)optionalHeader->ImageBase);
    printf("\tSectionAlignment : 0x%X\n", (unsigned int)optionalHeader->SectionAlignment);
    printf("\tFileAlignment : 0x%X\n", (unsigned int)optionalHeader->FileAlignment);
    printf("\tMajorOperatingSystemVersion : 0x%X\n", (unsigned int)optionalHeader->MajorOperatingSystemVersion);
    printf("\tMinorOperatingSystemVersion : 0x%X\n", (unsigned int)optionalHeader->MinorOperatingSystemVersion);
    printf("\tMajorImageVersion : 0x%X\n", (unsigned int)optionalHeader->MajorImageVersion);
    printf("\tMinorImageVersion : 0x%X\n", (unsigned int)optionalHeader->MinorImageVersion);
    printf("\tMajorSubsystemVersion : 0x%X\n", (unsigned int)optionalHeader->MajorSubsystemVersion);
    printf("\tMinorSubsystemVersion : 0x%X\n", (unsigned int)optionalHeader->MinorSubsystemVersion);
    printf("\tWin32VersionValue : 0x%X\n", (unsigned int)optionalHeader->Win32VersionValue);
    printf("\tSizeOfImage : 0x%X\n", (unsigned int)optionalHeader->SizeOfImage);
    printf("\tSizeOfHeaders : 0x%X\n", (unsigned int)optionalHeader->SizeOfHeaders);
    printf("\tCheckSum : 0x%X\n", (unsigned int)optionalHeader->CheckSum);
    printf("\tSubsystem : 0x%X %s\n", (unsigned int)optionalHeader->Subsystem, GetSubsystem(optionalHeader->Subsystem));
    printf("\tDllCharacteristics : 0x%X\n", (unsigned int)optionalHeader->DllCharacteristics);
    printf("\tSizeOfStackReserve : 0x%X\n", (unsigned int)optionalHeader->SizeOfStackReserve);
    printf("\tSizeOfStackCommit : 0x%X\n", (unsigned int)optionalHeader->SizeOfStackCommit);
    printf("\tSizeOfHeapReserve : 0x%X\n", (unsigned int)optionalHeader->SizeOfHeapReserve);
    printf("\tSizeOfHeapCommit : 0x%X\n", (unsigned int)optionalHeader->SizeOfHeapCommit);
    printf("\tLoaderFlags : 0x%X\n", (unsigned int)optionalHeader->LoaderFlags);
    printf("\tNumberOfRvaAndSizes : 0x%X\n", (unsigned int)optionalHeader->NumberOfRvaAndSizes);
    DisplayDataDirectories(optionalHeader->DataDirectory);
}
void DisplayOptionalHeader64(const IMAGE_OPTIONAL_HEADER64* optionalHeader)
{
    printf("\n[+] OPTIONAL HEADER\n");
    printf("\tMagic : 0x%X\n", (unsigned int)optionalHeader->Magic);
    printf("\tMajorLinkerVersion : 0x%X\n", (unsigned int)optionalHeader->MajorLinkerVersion);
    printf("\tMinorLinkerVersion : 0x%X\n", (unsigned int)optionalHeader->MinorLinkerVersion);
    printf("\tSizeOfCode : 0x%X\n", (unsigned int)optionalHeader->SizeOfCode);
    printf("\tSizeOfInitializedData : 0x%X\n", (unsigned int)optionalHeader->SizeOfInitializedData);
    printf("\tSizeOfUninitializedData : 0x%X\n", (unsigned int)optionalHeader->SizeOfUninitializedData);
    printf("\tAddressOfEntryPoint : 0x%X\n", (unsigned int)optionalHeader->AddressOfEntryPoint);
    printf("\tBaseOfCode : 0x%X\n", (unsigned int)optionalHeader->BaseOfCode);
    printf("\tImageBase : 0x%llX\n", (unsigned long long)optionalHeader->ImageBase);
    printf("\tSectionAlignment : 0x%X\n", (unsigned int)optionalHeader->SectionAlignment);
    printf("\tFileAlignment : 0x%X\n", (unsigned int)optionalHeader->FileAlignment);
    printf("\tMajorOperatingSystemVersion : 0x%X\n", (unsigned int)optionalHeader->MajorOperatingSystemVersion);
    printf("\tMinorOperatingSystemVersion : 0x%X\n", (unsigned int)optionalHeader->MinorOperatingSystemVersion);
    printf("\tMajorImageVersion : 0x%X\n", (unsigned int)optionalHeader->MajorImageVersion);
    printf("\tMinorImageVersion : 0x%X\n", (unsigned int)optionalHeader->MinorImageVersion);
    printf("\tMajorSubsystemVersion : 0x%X\n", (unsigned int)optionalHeader->MajorSubsystemVersion);
    printf("\tMinorSubsystemVersion : 0x%X\n", (unsigned int)optionalHeader->MinorSubsystemVersion);
    printf("\tWin32VersionValue : 0x%X\n", (unsigned int)optionalHeader->Win32VersionValue);
    printf("\tSizeOfImage : 0x%X\n", (unsigned int)optionalHeader->SizeOfImage);
    printf("\tSizeOfHeaders : 0x%X\n", (unsigned int)optionalHeader->SizeOfHeaders);
    printf("\tCheckSum : 0x%X\n", (unsigned int)optionalHeader->CheckSum);
    printf("\tSubsystem : 0x%X %s\n", (unsigned int)optionalHeader->Subsystem, GetSubsystem(optionalHeader->Subsystem));
    printf("\tDllCharacteristics : 0x%X\n", (unsigned int)optionalHeader->DllCharacteristics);
    printf("\tSizeOfStackReserve : 0x%X\n", (unsigned int)optionalHeader->SizeOfStackReserve);
    printf("\tSizeOfStackCommit : 0x%X\n", (unsigned int)optionalHeader->SizeOfStackCommit);
    printf("\tSizeOfHeapReserve : 0x%X\n", (unsigned int)optionalHeader->SizeOfHeapReserve);
    printf("\tSizeOfHeapCommit : 0x%X\n", (unsigned int)optionalHeader->SizeOfHeapCommit);
    printf("\tLoaderFlags : 0x%X\n", (unsigned int)optionalHeader->LoaderFlags);
    printf("\tNumberOfRvaAndSizes : 0x%X\n", (unsigned int)optionalHeader->NumberOfRvaAndSizes);
    DisplayDataDirectories(optionalHeader->DataDirectory);
}
void DisplayDataDirectories(const IMAGE_DATA_DIRECTORY* imageDataDirectory)
{
    printf("\n[+] DATA DIRECTORIES\n");
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i, ++imageDataDirectory)
    {
        if (imageDataDirectory->VirtualAddress == 0)
            continue;
        printf("\tDataDirectory (%s) VirtualAddress : 0x%X\n", GetDataDirectoryName(i), (unsigned int)imageDataDirectory->VirtualAddress);
        printf("\tDataDirectory (%s) Size : 0x%X\n\n", GetDataDirectoryName(i), (unsigned int)imageDataDirectory->Size);
    }
}
