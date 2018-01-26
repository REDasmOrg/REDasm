#ifndef PE_CONSTANTS_H
#define PE_CONSTANTS_H

// Signatures
#define IMAGE_DOS_SIGNATURE                               0x5A4D
#define IMAGE_NT_SIGNATURE                            0x00004550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC                      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC                      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC                       0x107

// Architecture
#define IMAGE_FILE_MACHINE_AM33                            0x1d3
#define IMAGE_FILE_MACHINE_AMD64                          0x8664
#define IMAGE_FILE_MACHINE_ARM                             0x1c0
#define IMAGE_FILE_MACHINE_EBC                             0xebc
#define IMAGE_FILE_MACHINE_I386                            0x14c
#define IMAGE_FILE_MACHINE_IA64                            0x200
#define IMAGE_FILE_MACHINE_M32R                           0x9041
#define IMAGE_FILE_MACHINE_MIPS16                          0x266
#define IMAGE_FILE_MACHINE_MIPSFPU                         0x366
#define IMAGE_FILE_MACHINE_MIPSFPU16                       0x466
#define IMAGE_FILE_MACHINE_POWERPC                         0x1f0
#define IMAGE_FILE_MACHINE_POWERPCFP                       0x1f1
#define IMAGE_FILE_MACHINE_R4000                           0x166
#define IMAGE_FILE_MACHINE_SH3                             0x1a2
#define IMAGE_FILE_MACHINE_SH3E                           0x01a4
#define IMAGE_FILE_MACHINE_SH3DSP                          0x1a3
#define IMAGE_FILE_MACHINE_SH4                             0x1a6
#define IMAGE_FILE_MACHINE_SH5                             0x1a8
#define IMAGE_FILE_MACHINE_THUMB                           0x1c2
#define IMAGE_FILE_MACHINE_WCEMIPSV2                       0x169
#define IMAGE_FILE_MACHINE_R3000                           0x162
#define IMAGE_FILE_MACHINE_R10000                          0x168
#define IMAGE_FILE_MACHINE_ALPHA                           0x184
#define IMAGE_FILE_MACHINE_ALPHA64                        0x0284
#define IMAGE_FILE_MACHINE_AXP64      IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_CEE                            0xC0EE
#define IMAGE_FILE_MACHINE_TRICORE                        0x0520
#define IMAGE_FILE_MACHINE_CEF                            0x0CEF
// Sections
#define IMAGE_SIZEOF_SHORT_NAME                                8

#define IMAGE_SCN_MEM_DISCARDABLE                     0x02000000
#define IMAGE_SCN_MEM_EXECUTE                         0x20000000
#define IMAGE_SCN_MEM_READ                            0x40000000
#define IMAGE_SCN_MEM_WRITE                           0x80000000

#define IMAGE_SCN_CNT_CODE                            0x00000020  // Section contains code
#define IMAGE_SCN_CNT_INITIALIZED_DATA                0x00000040  // Section contains initialized data
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA              0x00000080  // Section contains uninitialized data

// Data Directory
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES                      16

#define IMAGE_DIRECTORY_ENTRY_EXPORT                                              0  // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT                                              1  // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE                                            2  // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION                                           3  // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY                                            4  // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC                                           5  // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG                                               6  // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE                                        7  // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR                                           8  // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS                                                 9  // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG                                        10  // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT                                       11  // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT                                                12  // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT                                       13  // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR                                     14  // COM Runtime descriptor
#define IMAGE_DIRECTORY_ENTRY_DOTNET           IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR  // .NET descriptor

// Import Table
#define IMAGE_ORDINAL_FLAG64               0x8000000000000000ULL
#define IMAGE_ORDINAL_FLAG32                          0x80000000

// Resource Directory
#define IMAGE_RESOURCE_NAME_IS_STRING                 0x80000000
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY              0x80000000

// Relocations Directory
#define IMAGE_REL_BASED_ABSOLUTE                               0
#define IMAGE_REL_BASED_HIGH                                   1
#define IMAGE_REL_BASED_LOW                                    2
#define IMAGE_REL_BASED_HIGHLOW                                3
#define IMAGE_REL_BASED_HIGHADJ                                4
#define IMAGE_REL_BASED_MIPS_JMPADDR                           5
#define IMAGE_REL_BASED_SECTION                                6
#define IMAGE_REL_BASED_REL32                                  7

#define IMAGE_REL_BASED_MIPS_JMPADDR16                         9
#define IMAGE_REL_BASED_IA64_IMM64                             9
#define IMAGE_REL_BASED_DIR64                                 10
#define IMAGE_REL_BASED_HIGH3ADJ                              11

// Debug Info
#define IMAGE_DEBUG_TYPE_UNKNOWN                               0
#define IMAGE_DEBUG_TYPE_COFF                                  1
#define IMAGE_DEBUG_TYPE_CODEVIEW                              2
#define IMAGE_DEBUG_TYPE_FPO                                   3
#define IMAGE_DEBUG_TYPE_MISC                                  4
#define IMAGE_DEBUG_TYPE_EXCEPTION                             5
#define IMAGE_DEBUG_TYPE_FIXUP                                 6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC                           7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC                         8
#define IMAGE_DEBUG_TYPE_BORLAND                               9
#define IMAGE_DEBUG_TYPE_RESERVED10                           10
#define IMAGE_DEBUG_TYPE_CLSID                                11

#endif // PE_CONSTANTS_H
