#ifndef XBE_HEADER_H
#define XBE_HEADER_H

#include "../../redasm.h"

#define XBE_MAGIC_NUMBER               0x48454258 // 'XBEH'
#define XBE_ORDINAL_FLAG               0x80000000
#define XBE_ENTRYPOINT_XOR_DEBUG       0x94859D4B
#define XBE_ENTRYPOINT_XOR_RETAIL      0xA8FC57AB
#define XBE_KERNEL_XOR_DEBUG           0xEFB1F152
#define XBE_KERNEL_XOR_RETAIL          0x5B6D40B6

#define XBE_GAME_REGION_NA             0x00000001
#define XBE_GAME_REGION_JAPAN          0x00000002
#define XBE_GAME_REGION_RESTOFWORLD    0x00000004
#define XBE_GAME_REGION_MANUFACTURING  0x80000000

#define XBE_TITLENAME_SIZE        40

namespace REDasm {

struct XbeImageHeader
{
    u32 Magic;
    u8 DigitalSig[256];
    u32 BaseAddress, SizeOfHeaders, SizeOfImage, SizeOfImageHeader;
    u32 TimeDateStamp, CertificateAddress, NumberOfSections, SectionHeader;

    struct {
        unsigned int MountUtilityDrive  : 1;
        unsigned int FormatUtilityDrive : 1;
        unsigned int Limit64MB          : 1;
        unsigned int DontSetupHardDisk  : 1;
        unsigned int Unused             : 4;
        unsigned int UnusedB1           : 8;
        unsigned int UnusedB2           : 8;
        unsigned int UnusedB3           : 8;
    } InitFlags;

    u32 EntryPoint, TlsAddress;
    u32 PeStackCommit, PeHeapReserve, PeHeapCommit;
    u32 PeBaseAddress, PeSizeOfImage;
    u32 PeCheckSum, PeTimeDateStamp;
    u32 DebugPathName, DebugFileName, DebugUnicodeFileName;
    u32 KernelImageThunk, NonKernelImportDirectory;
    u32 NumberOfLibraryVersions, LibraryVersions, XApiVersionAddress;
    u32 LogoBitmap, LogoBitmapSize;
};

struct XbeCertificate
{
    u32 Size, TimeDateStamp, TitleId;
    u16 TitleName[XBE_TITLENAME_SIZE];
    u32 AlternateTitleId[0x10];
    u32 AllowedMedia, GameRegion, GameRatings;
    u32 DiskNumber, Version;
    u8 LanKey[16], SignatureKey[16], AltSignatureKey[16][16];
};

struct XbeSectionHeader
{
    struct {
        unsigned int Writable     : 1;
        unsigned int Preload      : 1;
        unsigned int Executable   : 1;
        unsigned int InsertedFile : 1;
        unsigned int HeadPageRO   : 1;
        unsigned int TailPageRO   : 1;
        unsigned int UnusedA1     : 1;
        unsigned int UnusedA2     : 1;
        unsigned int UnusedB1     : 8;
        unsigned int UnusedB2     : 8;
        unsigned int UnusedB3     : 8;
    } Flags;

    u32 VirtualAddress, VirtualSize;
    u32 RawAddress, RawSize;
    u32 SectionName, SectionRefs;
    u32 HeadSharedRefCount, TailSharedRefCount;
    u8 SectionDigest[20];
};

} // namespace REDasm

#endif // XBE_HEADER_H
