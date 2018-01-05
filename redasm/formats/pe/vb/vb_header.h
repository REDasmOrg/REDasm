#ifndef VB_HEADER_H
#define VB_HEADER_H

#include "../../../redasm.h"
#include "../pe_common.h"

namespace REDasm {

struct VBHeader
{
    char szVbMagic[4];         // “VB5!” String
    u16 wRuntimeBuild;         // Build of the VB6 Runtime
    char szLangDll[14];        // Language Extension DLL
    char szSecLangDll[14];     // 2nd Language Extension DLL
    u16 wRuntimeRevision;      // Internal Runtime Revision
    u32 dwLCID;                // LCID of Language DLL
    u32 dwSecLCID;             // LCID of 2nd Language DLL
    u32 lpSubMain;             // Pointer to Sub Main Code
    u32 lpProjectData;         // Pointer to Project Data
    u32 fMdlIntCtls;           // VB Control Flags for IDs < 32
    u32 fMdlIntCtls2;          // VB Control Flags for IDs > 32
    u32 dwThreadFlags;         // Threading Mode
    u32 dwThreadCount;         // Threads to support in pool
    u16 wFormCount;            // Number of forms present
    u16 wExternalCount;        // Number of external controls
    u32 dwThunkCount;          // Number of thunks to create
    u32 lpGuiTable;            // Pointer to GUI Table
    u32 lpExternalCompTable;   // Pointer to External Component Table
    u32 lpComRegisterData;     // Pointer to COM Information
    u32 bszProjectDescription; // Offset to Project Description (base:VbHeader)
    u32 bszProjectExeName;     // Offset to Project EXE Name (base:VbHeader)
    u32 bszProjectHelpFile;    // Offset to Project Help File (base:VbHeader)
    u32 bszProjectName;        // Offset to Project Name (base:VbHeader)
};

struct VBProjectInfo
{
    u32 dwVersion;                  // Version
    u32 lpObjectTable;              // Pointer to the Object Table
    u32 dwNull;                     // Unused value after compilation.
    u32 lpCodeStart;                // Points to start of code (Unused)
    u32 lpCodeEnd;                  // Points to end of code (Unused)
    u32 dwDataSize;                 // Size of VB Object Structures (Unused)
    u32 lpThreadSpace;              // Pointer to Pointer to Thread Object
    u32 lpVbaSeh;                   // Pointer to VBA Exception Handler
    u32 lpNativeCode;               // Pointer to .DATA section
    wchar_t szPathInformation[264]; // Contains Path and ID string. < SP6
    u32 lpExternalTable;            // Pointer to External Table
    u32 dwExternalCount;            // Objects in the External Table
};

struct VBGuiTable
{
    u32 lpSectionHeader; // Address of section header
    u8 dwReserved[59];   // Unused Bytes
    u32 dwFormSize;      // Block size, describing the form and its controls
    u32 dwReserved1;     //
    u32 lpFormData;      // Pointer to the block describing the form and its controls
    u32 dwReserved2;     //
};

struct VBObjectTable
{
    u32 lpHeapLink;       // Always set to 0 after compiling (Unused)
    u32 lpExecProj;       // Pointer to VB Project Exec COM Object
    u32 lpObjectTreeInfo; //
    u32 dwReserved;       // Always set to -1 after compiling (Unused)
    u32 dwNull;           // (Unused)
    u32 lpProjectObject;  // Pointer to in-memory Project Data
    GUID uuidObject;      // GUID of the Object Table
    u16 fCompileState;    // Internal flag used during compilation
    u16 wTotalObjects;    // Total objects present in Project
    u16 wCompiledObjects; // Equal to above after compiling
    u16 wObjectsInUse;    // Usually equal to above after compile
    u32 lpPubObjArray;    // Pointer to Public Object Descriptors
    u32 fIdeFlag;         // Flag/Pointer used in IDE only
    u32 lpIdeData;        // Flag/Pointer used in IDE only
    u32 lpIdeData2;       // Flag/Pointer used in IDE only
    u32 lpszProjectName;  // Pointer to Project Name
    LCID dwLcid;          // LCID of Project
    LCID dwLcid2;         // Alternate LCID of Project
    u32 lpIdeData3;       // Flag/Pointer used in IDE only
    u32 dwIdentifier;     // Template Version of Structure
};

struct VBObjectTreeInfo
{
    u32 lpHeapLink;           // Always set to 0 after compiling (Unused)
    u32 lpObjectTable;        // Back-Pointer to the Object Table
    u32 dwReserved;           // Always set to -1 after compiling (Unused)
    u32 dwUnused;             // (Unused)
    u32 lpFormList;           // Pointer to Form Descriptor Pointers
    u32 dwUnused2;            // (Unused)
    u32 szProjectDescription; // Pointer to Project Description
    u32 szProjectHelpFile;    // Pointer to Project Help File
    u32 dwReserved2;          // Always set to -1 after compiling (Unused)
    u32 dwHelpContextId;      // Help Context ID set in Project Settings
};

struct VBPublicObjectDescriptor // ModulesList
{
    u32 lpObjectInfo;   // Pointer to the Object Info for this Object // VbObjectInfo/FormDescriptor
    u32 dwReserved;     // -1
    u32 lpPublicBytes;  // Pointer to Public Variable Size integers
    u32 lpStaticBytes;  // Pointer to Static Variable Size integers
    u32 lpModulePublic; // Pointer to Public Variables in DATA section
    u32 lpModuleStatic; // Pointer to Static Variables in DATA section
    u32 lpszObjectName; // Name of the Object
    u32 dwMethodCount;  // Number of Methods in Object
    u32 lpMethodNames;  // If present, pointer to Method names array
    u32 bStaticVars;    // Offset to where to copy Static Variables
    u32 fObjectType;    // Flags defining the Object Type
    u32 dwNull;         // Not valid after compilation
};

struct VBObjectInfo // ModuleDescriptor
{
    u16 wRefCount;       // Always 1 after compilation
    u16 wObjectIndex;    // Index of this Object in the public descriptor array
    u32 lpObjectTable;   // Pointer to the Object Table
    u32 lpIdeData;       // Zero after compilation (Used in IDE only)
    u32 lpPrivateObject; // Pointer to Private Object Descriptor
    u32 dwReserved;      // Always -1 after compilation
    u32 dwNull;          // Unused
    u32 lpObject;        // Back-Pointer to Public Object Descriptor
    u32 lpProjectData;   // Pointer to in-memory Project Object
    u16 wMethodCount;    // Number of Methods
    u16 wMethodCount2;   // Zeroed out after compilation (IDE only)
    u32 lpMethods;       // Pointer to Array of Methods
    u16 wConstants;      // Number of Constants in Constant Pool
    u16 wMaxConstants;   // Constants to allocate in Constant Pool
    u32 lpIdeData2;      // Valid in IDE only
    u32 lpIdeData3;      // Valid in IDE only
    u32 lpConstants;     // Pointer to Constants Pool
};

struct VBObjectInfoOptional // FormDescriptor
{
    VBObjectInfo base;      //
    u32 dwObjectGuids;      // How many GUIDs to Register. 2 = Designer
    u32 lpObjectGuid;       // Unique GUID of the Object?
    u32 dwNull;             // Unused
    u32 lpuuidObjectTypes;  // Pointer to Array of Object Interface GUIDs
    u32 dwObjectTypeGuids;  // How many GUIDs in the Array above
    u32 lpControls2;        // Usually the same as lpControls
    u32 dwNull2;            // Unused
    u32 lpObjectGuid2;      // Pointer to Array of Object GUIDs
    u32 dwControlCount;     // Number of Controls in array below
    u32 lpControls;         // Pointer to Controls Array
    u16 wEventCount;        // Number of Events in Event Array
    u16 wPCodeCount;        // Number of P-Codes used by this Object
    u16 bWInitializeEvent;  // Offset to Initialize Event from Event Table
    u16 bWTerminateEvent;   // Offset to Terminate Event in Event Table
    u32 lpEvents;           // Pointer to Events Array
    u32 lpBasicClassObject; // Pointer to in-memory Class Objects
    u32 dwNull3;            // Unused
    u32 lpIdeData;          // Only valid in IDE
};

struct VBControlInfo
{
    u32 fControlType;   // Type of control
    u16 wEventCount;    // Number of Event Handlers supported
    u16 bWEventsOffset; // Offset in to Memory struct to copy Events
    u32 lpGuid;         // Pointer to GUID of this Control
    u32 dwIndex;        // Index ID of this Control
    u32 dwNull;         // Unused
    u32 dwNull2;        // Unused
    u32 lpEventInfo;    // Pointer to Event Handler Table
    u32 lpIdeData;      // Valid in IDE only
    u32 lpszName;       // Name of this Control
    u32 dwIndexCopy;    // Secondary Index ID of this Control
};

struct VBEventInfo // LocalDispatcher
{
    u32 dwNull;                      //
    u32 lpControlsList;              // back-pointer to VbControlInfo
    u32 lpFormDescriptor;            // back-pointer to VbObjectInfoOptional
    u32 lpEVENT_SINK_QueryInterface; //
    u32 lpEVENT_SINK_AddRef;         //
    u32 lpEVENT_SINK_Release;        //
    u32 lpEvents[1];                 //
};

}

#endif // VB_HEADER_H
