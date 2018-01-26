#ifndef DOTNET_HEADER_H
#define DOTNET_HEADER_H

// http://ntcore.com/files/dotnetformat.htm

#include "../../../redasm.h"
#include "../pe_headers.h"

#define PE_IS_DOTNET20(corheader) (corheader.MajorRuntimeVersion >= 2)

namespace REDasm {

namespace ReplacesCorHdrNumericDefines {

enum: u32 {
    COMIMAGE_FLAGS_ILONLY               = 0x00000001,
    COMIMAGE_FLAGS_32BITREQUIRED        = 0x00000002,
    COMIMAGE_FLAGS_IL_LIBRARY           = 0x00000004,
    COMIMAGE_FLAGS_STRONGNAMESIGNED     = 0x00000008,
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT    = 0x00000010,
    COMIMAGE_FLAGS_TRACKDEBUGDATA       = 0x00010000,
};

}

struct ImageCorHeader
{
    u32 cb;
    u16 MajorRuntimeVersion, MinorRuntimeVersion;
};

struct ImageCor20Header
{
    ImageCorHeader Header;

    // Symbol table and startup information
    ImageDataDirectory MetaData;
    u32 Flags;
    union { u32 EntryPointToken, EntryPointRVA; };

    // Binding information
    ImageDataDirectory Resources, StrongNameSignature;

    // Regular fixup and binding information
    ImageDataDirectory CodeManagerTable, VTableFixups, ExportAddressTableJumps;

    // Precompiled image info (internal use only)
    ImageDataDirectory ManagedNativeHeader;
};

struct ImageCor20MetaData
{
    u32 Signature;
    u16 MajorVersion, MinorVersion;
    u32 Reserved, VersionLength;
    char VersionString[];
};

struct ImageCor20TablesHeader
{
    u32 Reserved1;
    u8 MajorVersion, MinorVersion, HeapOffsetSizes, Reserved2;
    u64 MaskValid, MaskSorted;
};

struct ImageStreamHeader
{
    u32 Offset, Size;
    char szAlignedAnsi[];
};

} // namespace REDasm

#endif // DOTNET_HEADER_H
