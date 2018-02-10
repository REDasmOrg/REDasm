#ifndef DOTNET_TABLES_H
#define DOTNET_TABLES_H

#include "../../../redasm.h"

#define DOTNET_TAG_F(n) u8 n##_tag; u32 n

namespace REDasm {

struct CorTable
{
    struct { u16 generation; u32 name, mvId, encId, encBaseId; } module;
    struct { DOTNET_TAG_F(resolutionScope); u32 typeName, typeNamespace; } typeRef;
    struct { u32 flags, typeName, typeNamespace; DOTNET_TAG_F(extends); u32 fieldList, methodList; } typeDef;
    struct { u16 flags; u32 name, signature; } fieldDef;
    struct { u32 rva; u16 implFlags, flags; u32 name, signature, paramList; } methodDef;
    struct { u16 flags, sequence; u32 name; } paramDef;
    struct { u32 classIdx; DOTNET_TAG_F(interfaceIdx); } interfaceImpl;
    struct { DOTNET_TAG_F(classIdx); u32 name, signature; } memberRef;
    struct { u16 type; DOTNET_TAG_F(parent); u32 value; } constant;
    struct { DOTNET_TAG_F(parent); DOTNET_TAG_F(type); u32 value; } customAttribute;
    struct { DOTNET_TAG_F(parent); u32 nativeType; } fieldMarshal;
    struct { u16 action; DOTNET_TAG_F(parent); u32 permissionSet; } declSecurity;
    struct { u16 packingSize; u32 classSize, parent; } classLayout;
    struct { u32 offset, field; } fieldLayout;
    struct { u32 signature; } standaloneSig;
    struct { u32 parent, eventList; } eventMap;
    struct { u16 eventFlags; u32 name; DOTNET_TAG_F(eventType); } event;
    struct { u32 parent, propertyList; } propertyMap;
    struct { u32 flags, name, type; } property;
    struct { u16 semantics; u32 method; DOTNET_TAG_F(association); } methodSemantics;
    struct { u32 classIdx; DOTNET_TAG_F(methodBody); DOTNET_TAG_F(methodDeclaration); } methodImpl;
    struct { u32 name; } moduleRef;
    struct { u32 signature; } typeSpec;
    struct { u16 mappingFlags; DOTNET_TAG_F(memberForwarded); u32 importName, importScope; } implMap;
    struct { u32 rva, field; } fieldRVA;
    struct { u32 hashAlgId; u16 major, minor, build, revision; u32 flags, publicKey, name, culture; } assembly;
    struct { u32 processor; } assemblyProcessor;
    struct { u32 platformId, major, minor; } assemblyOS;
    struct { u16 major, minor, build, revision; u32 flags, publicKeyOrToken, name, culture, hashValue; } assemblyRef;
    struct { u32 processor, assemblyRef; } assemblyRefProcessor;
    struct { u32 platformId, major, minor, assemblyRef; } assemblyRefOS;
    struct { u32 flags, name, hashValue; } file;
    struct { u32 flags, typeDefId, typeName, typeNamespace; DOTNET_TAG_F(implementation); } exportedType;
    struct { u32 offset, flags, name; DOTNET_TAG_F(implementation); } manifestResource;
    struct { u32 nestedClass, enclosingClass; } nestedClass;
    struct { u16 number, flags; DOTNET_TAG_F(owner); u32 name; } genericParam;
    struct { u32 owner; DOTNET_TAG_F(constraint); } genericParamConstraint;
};

typedef std::unique_ptr<CorTable> CorTablePtr;
typedef std::vector<CorTablePtr> CorTableRows;

struct CorTables
{
    u8 stringoffsize, guidoffsize, bloboffsize;

    std::map<u32, CorTableRows> items;
    std::map<u32, u32> rows;
};

} // namespace REDasm

#endif // DOTNET_TABLES_H
