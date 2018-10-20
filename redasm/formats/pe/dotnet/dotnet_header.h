#ifndef DOTNET_HEADER_H
#define DOTNET_HEADER_H

/*
 * http://ntcore.com/files/dotnetformat.htm
 * https://www.red-gate.com/simple-talk/blogs/anatomy-of-a-net-assembly-clr-metadata-1
 * https://www.red-gate.com/simple-talk/blogs/anatomy-of-a-net-assembly-clr-metadata-2
 * https://www.red-gate.com/simple-talk/blogs/anatomy-of-a-net-assembly-clr-metadata-3
 */

#include "../../../redasm.h"
#include "../pe_headers.h"

#define PE_IS_DOTNET20(corheader) (corheader.MajorRuntimeVersion >= 2)

namespace REDasm {

namespace ReplacesCorHdrNumericDefines {

enum: u32 {
    COMIMAGE_FLAGS_ILONLY            = 0x00000001, COMIMAGE_FLAGS_32BITREQUIRED    = 0x00000002,
    COMIMAGE_FLAGS_IL_LIBRARY        = 0x00000004, COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008,
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010, COMIMAGE_FLAGS_TRACKDEBUGDATA   = 0x00010000,
};

}

namespace CorMetadataTables {

enum: u32 {
    Module                 = 0,  TypeRef         = 1,  TypeDef                = 2,  FieldDef         = 4,  MethodDef    = 6,  ParamDef             = 8,
    InterfaceImpl          = 9,  MemberRef       = 10, Constant               = 11, CustomAttribute  = 12, FieldMarshal = 13, DeclSecurity         = 14,
    ClassLayout            = 15, FieldLayout     = 16, StandaloneSig          = 17, EventMap         = 18, Event        = 20, PropertyMap          = 21,
    Property               = 23, MethodSemantics = 24, MethodImpl             = 25, ModuleRef        = 26, TypeSpec     = 27, ImplMap              = 28,
    FieldRVA               = 29, Assembly        = 32, AssemblyProcessor      = 33, AssemblyOS       = 34, AssemblyRef  = 35, AssemblyRefProcessor = 36,
    AssemblyRefOS          = 37, File            = 38, ExportedType           = 39, ManifestResource = 40, NestedClass  = 41, GenericParam         = 42,
    GenericParamConstraint = 44
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
    char VersionString[1];
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
    char szAlignedAnsi[1];
};

} // namespace REDasm

#endif // DOTNET_HEADER_H
