#include "dotnet.h"
#include <cstring>
#include <iostream>

#define PUSH_TABLE(t) _tables.push_back(CorMetadataTables::t); \
                      _dispatcher[CorMetadataTables::t] = &PeDotNet::get##t

namespace REDasm {

std::list<u32> PeDotNet::_tables;
PeDotNet::TableDispatcher PeDotNet::_dispatcher;

PeDotNet::PeDotNet()
{

}

std::string PeDotNet::getVersion(ImageCor20MetaData *cormetadata)
{
    return std::string(reinterpret_cast<char*>(&cormetadata->VersionString));
}

u16 PeDotNet::getNumberOfStreams(ImageCor20MetaData *cormetadata)
{
    u16* p = reinterpret_cast<u16*>(reinterpret_cast<u8*>(&cormetadata->VersionString) + cormetadata->VersionLength +
                                    sizeof(u16)); // Flags

    return *p;
}

ImageStreamHeader *PeDotNet::getStream(ImageCor20MetaData *cormetadata, const std::string& id)
{
    u16 n = PeDotNet::getNumberOfStreams(cormetadata);
    u8* p = reinterpret_cast<u8*>(&cormetadata->VersionString) + (cormetadata->VersionLength + (sizeof(u16) * 2)); // Flags + NumberOfStreams
    ImageStreamHeader* pstreamheader = reinterpret_cast<ImageStreamHeader*>(p);

    for(u16 i = 0; i < n; i++)
    {
        if(std::string(pstreamheader->szAlignedAnsi) == id)
            return pstreamheader;

        size_t len = std::strlen(pstreamheader->szAlignedAnsi) + 1;
        pstreamheader = reinterpret_cast<ImageStreamHeader*>(reinterpret_cast<u8*>(pstreamheader) +
                                                             ((sizeof(u32) * 2) + REDasm::aligned(len, 4)));
    }

    REDasm::log("Cannot find Stream Id " + REDasm::quoted(id));
    return NULL;
}

bool PeDotNet::getTables(ImageCor20TablesHeader *cortablesheader, CorTables &tables)
{
    PeDotNet::initTables();
    tables.stringoffsize = PeDotNet::getSizeOfHeap(cortablesheader, 0);
    tables.guidoffsize = PeDotNet::getSizeOfHeap(cortablesheader, 1);
    tables.bloboffsize = PeDotNet::getSizeOfHeap(cortablesheader, 2);

    u32* tabledata = REDasm::relpointer<u32>(cortablesheader, sizeof(ImageCor20TablesHeader));

    // Read rows
    for(u64 i = 0; i < REDasm::bitwidth<u64>::value; i++)
    {
        u64 tablebit = (static_cast<u64>(1) << i);

        if(cortablesheader->MaskValid & tablebit)
        {
            tables.rows[i] = *tabledata;
            tabledata++;
        }
    }

    // Read columns
    for(auto rit = tables.rows.begin(); rit != tables.rows.end(); rit++)
    {
        auto it = _dispatcher.find(rit->first);

        if(it == _dispatcher.end())
        {
            REDasm::log("Cannot find table " + REDasm::quoted(rit->first));
            return false;
        }

        for(u32 i = 0 ; i < rit->second; i++)
        {
            CorTable table;
            it->second(&tabledata, tables, table);

            auto itt = tables.items.find(rit->first);

            if(itt != tables.items.end())
            {
                itt->second.push_back(table);
                continue;
            }

            CorTableRows tl;
            tl.push_back(table);
            tables.items[rit->first] = tl;
        }
    }

    return true;
}

u32 PeDotNet::getSizeOfHeap(ImageCor20TablesHeader *cortablesheader, u32 bitno)
{
    if(cortablesheader->HeapOffsetSizes & (1 << bitno))
        return sizeof(u32);

    return sizeof(u16);
}

u32 PeDotNet::getValueIdx(u32 **data, u32 offsize)
{
    if(offsize == sizeof(u32))
        return REDasm::readpointer<u32>(data);

    return REDasm::readpointer<u16>(data);
}

u32 PeDotNet::getTableIdx(u32 **data, const CorTables &tables, u32 table)
{
    if(tables.rows.at(table) > 0xFFFF)
        return REDasm::readpointer<u32>(data);

    return REDasm::readpointer<u16>(data);
}

u32 PeDotNet::getStringIdx(u32 **data, const CorTables &tables) { return PeDotNet::getValueIdx(data, tables.stringoffsize); }
u32 PeDotNet::getGuidIdx(u32 **data, const CorTables &tables) { return PeDotNet::getValueIdx(data, tables.guidoffsize); }
u32 PeDotNet::getBlobIdx(u32 **data, const CorTables &tables) { return PeDotNet::getValueIdx(data, tables.bloboffsize); }

void PeDotNet::initTables()
{
    if(!_tables.empty())
        return;

    PUSH_TABLE(Module);
    PUSH_TABLE(TypeRef);
    PUSH_TABLE(TypeDef);
    PUSH_TABLE(FieldDef);
    PUSH_TABLE(MethodDef);
    PUSH_TABLE(ParamDef);
    PUSH_TABLE(InterfaceImpl);
    PUSH_TABLE(MemberRef);
    PUSH_TABLE(Constant);
    PUSH_TABLE(CustomAttribute);
    PUSH_TABLE(FieldMarshal);
    PUSH_TABLE(DeclSecurity);
    PUSH_TABLE(ClassLayout);
    PUSH_TABLE(FieldLayout);
    PUSH_TABLE(StandaloneSig);
    PUSH_TABLE(EventMap);
    PUSH_TABLE(Event);
    PUSH_TABLE(PropertyMap);
    PUSH_TABLE(Property);
    PUSH_TABLE(MethodSemantics);
    PUSH_TABLE(MethodImpl);
    PUSH_TABLE(ModuleRef);
    PUSH_TABLE(TypeSpec);
    PUSH_TABLE(ImplMap);
    PUSH_TABLE(FieldRVA);
    PUSH_TABLE(Assembly);
    PUSH_TABLE(AssemblyProcessor);
    PUSH_TABLE(AssemblyOS);
    PUSH_TABLE(AssemblyRef);
    PUSH_TABLE(AssemblyRefProcessor);
    PUSH_TABLE(AssemblyRefOS);
    PUSH_TABLE(File);
    PUSH_TABLE(ExportedType);
    PUSH_TABLE(ManifestResource);
    PUSH_TABLE(NestedClass);
    PUSH_TABLE(GenericParam);
    PUSH_TABLE(GenericParamConstraint);
}

void PeDotNet::getModule(u32 **data, const CorTables &tables, CorTable &table)
{
    table.module.generation = REDasm::readpointer<u16>(data);
    table.module.name = PeDotNet::getStringIdx(data, tables);
    table.module.mvId = PeDotNet::getGuidIdx(data, tables);
    table.module.encId = PeDotNet::getGuidIdx(data, tables);
    table.module.encBaseId = PeDotNet::getGuidIdx(data, tables);
}

void PeDotNet::getTypeRef(u32 **data, const CorTables &tables, CorTable &table)
{
    PeDotNet::getTaggedField(data, table.typeRef.resolutionScope,  table.typeRef.resolutionScope_tag, 2, tables,
                            {CorMetadataTables::Module, CorMetadataTables::ModuleRef, CorMetadataTables::Assembly, CorMetadataTables::AssemblyRef});

    table.typeRef.typeName = PeDotNet::getStringIdx(data, tables);
    table.typeRef.typeNamespace = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getTypeDef(u32 **data, const CorTables &tables, CorTable &table)
{
    table.typeDef.flags = REDasm::readpointer<u32>(data);
    table.typeDef.typeName = PeDotNet::getStringIdx(data, tables);
    table.typeDef.typeNamespace = PeDotNet::getStringIdx(data, tables);

    PeDotNet::getTaggedField(data, table.typeDef.extends,  table.typeDef.extends_tag, 2, tables,
                            {CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::TypeSpec });

    table.typeDef.fieldList = PeDotNet::getTableIdx(data, tables, CorMetadataTables::FieldDef);
    table.typeDef.methodList = PeDotNet::getTableIdx(data, tables, CorMetadataTables::MethodDef);
}

void PeDotNet::getFieldDef(u32 **data, const CorTables &tables, CorTable &table)
{
    table.fieldDef.flags = REDasm::readpointer<u16>(data);
    table.fieldDef.name = PeDotNet::getStringIdx(data, tables);
    table.fieldDef.signature = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getMethodDef(u32 **data, const CorTables &tables, CorTable &table)
{
    table.methodDef.rva = REDasm::readpointer<u32>(data);
    table.methodDef.implFlags = REDasm::readpointer<u16>(data);
    table.methodDef.flags = REDasm::readpointer<u16>(data);
    table.methodDef.name = PeDotNet::getStringIdx(data, tables);
    table.methodDef.signature = PeDotNet::getBlobIdx(data, tables);
    table.methodDef.paramList = PeDotNet::getTableIdx(data, tables, CorMetadataTables::ParamDef);
}

void PeDotNet::getParamDef(u32 **data, const CorTables &tables, CorTable &table)
{
    table.paramDef.flags = REDasm::readpointer<u16>(data);
    table.paramDef.sequence = REDasm::readpointer<u16>(data);
    table.paramDef.name = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getInterfaceImpl(u32 **data, const CorTables &tables, CorTable &table)
{
    table.interfaceImpl.classIdx = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);

    PeDotNet::getTaggedField(data, table.interfaceImpl.interfaceIdx,  table.interfaceImpl.interfaceIdx_tag, 2, tables,
                            {CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::TypeSpec });
}

void PeDotNet::getMemberRef(u32 **data, const CorTables &tables, CorTable &table)
{
    PeDotNet::getTaggedField(data, table.memberRef.classIdx,  table.memberRef.classIdx_tag, 3, tables,
                            {CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::ModuleRef,
                             CorMetadataTables::MethodDef, CorMetadataTables::TypeSpec });

    table.memberRef.name = PeDotNet::getStringIdx(data, tables);
    table.memberRef.signature = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getConstant(u32 **data, const CorTables &tables, CorTable &table)
{
    table.constant.type = REDasm::readpointer<u16>(data);

    PeDotNet::getTaggedField(data, table.constant.parent,  table.constant.parent_tag, 2, tables,
                            {CorMetadataTables::FieldDef, CorMetadataTables::ParamDef, CorMetadataTables::Property });

    table.constant.value = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getCustomAttribute(u32 **data, const CorTables &tables, CorTable &table)
{
    PeDotNet::getTaggedField(data, table.customAttribute.parent,  table.customAttribute.parent_tag, 5, tables,
                            {CorMetadataTables::MethodDef, CorMetadataTables::FieldDef, CorMetadataTables::TypeRef,
                             CorMetadataTables::TypeDef, CorMetadataTables::ParamDef, CorMetadataTables::InterfaceImpl,
                             CorMetadataTables::MemberRef, CorMetadataTables::Module, /* CorMetaDataTables::Permission, */
                             CorMetadataTables::Property, CorMetadataTables::Event, CorMetadataTables::StandaloneSig,
                             CorMetadataTables::ModuleRef, CorMetadataTables::TypeSpec, CorMetadataTables::Assembly,
                             CorMetadataTables::AssemblyRef, CorMetadataTables::File, CorMetadataTables::ExportedType,
                             CorMetadataTables::ManifestResource});

    PeDotNet::getTaggedField(data, table.customAttribute.type, table.customAttribute.type_tag, 3, tables,
                            { CorMetadataTables::MethodDef, CorMetadataTables::MemberRef });

    table.customAttribute.value = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getFieldMarshal(u32 **data, const CorTables &tables, CorTable &table)
{
    PeDotNet::getTaggedField(data, table.fieldMarshal.parent, table.fieldMarshal.parent_tag, 1, tables,
                            { CorMetadataTables::FieldDef, CorMetadataTables::ParamDef });

    table.fieldMarshal.nativeType = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getDeclSecurity(u32 **data, const CorTables &tables, CorTable &table)
{
    table.declSecurity.action = REDasm::readpointer<u16>(data);

    PeDotNet::getTaggedField(data, table.declSecurity.parent, table.fieldMarshal.parent_tag, 2, tables,
                            { CorMetadataTables::TypeDef, CorMetadataTables::MethodDef, CorMetadataTables::Assembly });

    table.declSecurity.permissionSet = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getClassLayout(u32 **data, const CorTables &tables, CorTable &table)
{
    table.classLayout.packingSize = REDasm::readpointer<u16>(data);
    table.classLayout.classSize = REDasm::readpointer<u32>(data);
    table.classLayout.parent = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);
}

void PeDotNet::getFieldLayout(u32 **data, const CorTables &tables, CorTable &table)
{
    table.fieldLayout.offset = REDasm::readpointer<u32>(data);
    table.fieldLayout.field = PeDotNet::getTableIdx(data, tables, CorMetadataTables::FieldDef);
}

void PeDotNet::getStandaloneSig(u32 **data, const CorTables &tables, CorTable &table)
{
    table.standaloneSig.signature = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getEventMap(u32 **data, const CorTables &tables, CorTable &table)
{
    table.eventMap.parent = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);
    table.eventMap.eventList = PeDotNet::getTableIdx(data, tables, CorMetadataTables::Event);
}

void PeDotNet::getEvent(u32 **data, const CorTables &tables, CorTable &table)
{
    table.event.eventFlags = REDasm::readpointer<u16>(data);
    table.event.name = PeDotNet::getStringIdx(data, tables);

    PeDotNet::getTaggedField(data, table.event.eventType,  table.event.eventType_tag, 2, tables,
                            {CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::TypeSpec });
}

void PeDotNet::getPropertyMap(u32 **data, const CorTables &tables, CorTable &table)
{
    table.propertyMap.parent = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);
    table.propertyMap.propertyList = PeDotNet::getTableIdx(data, tables, CorMetadataTables::Property);
}

void PeDotNet::getProperty(u32 **data, const CorTables &tables, CorTable &table)
{
    table.property.flags = REDasm::readpointer<u16>(data);
    table.property.name = PeDotNet::getStringIdx(data, tables);
    table.property.type = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getMethodSemantics(u32 **data, const CorTables &tables, CorTable &table)
{
    table.methodSemantics.semantics = REDasm::readpointer<u16>(data);
    table.methodSemantics.method = PeDotNet::getTableIdx(data, tables, CorMetadataTables::MethodDef);

    PeDotNet::getTaggedField(data, table.methodSemantics.association, table.methodSemantics.association_tag, 1, tables,
                            { CorMetadataTables::Event, CorMetadataTables::Property});
}

void PeDotNet::getMethodImpl(u32 **data, const CorTables &tables, CorTable &table)
{
    table.methodImpl.classIdx = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);

    PeDotNet::getTaggedField(data, table.methodImpl.methodBody, table.methodImpl.methodBody_tag, 1, tables,
                            { CorMetadataTables::MethodDef, CorMetadataTables::MemberRef});

    PeDotNet::getTaggedField(data, table.methodImpl.methodDeclaration, table.methodImpl.methodDeclaration_tag, 1, tables,
                            { CorMetadataTables::MethodDef, CorMetadataTables::MemberRef});
}

void PeDotNet::getModuleRef(u32 **data, const CorTables &tables, CorTable &table)
{
    table.moduleRef.name = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getTypeSpec(u32 **data, const CorTables &tables, CorTable &table)
{
    table.typeSpec.signature = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getImplMap(u32 **data, const CorTables &tables, CorTable &table)
{
    table.implMap.mappingFlags = REDasm::readpointer<u16>(data);

    PeDotNet::getTaggedField(data, table.implMap.memberForwarded, table.implMap.memberForwarded_tag, 1, tables,
                            { CorMetadataTables::FieldDef, CorMetadataTables::MethodDef });

    table.implMap.importName = PeDotNet::getStringIdx(data, tables);
    table.implMap.importScope = PeDotNet::getTableIdx(data, tables, CorMetadataTables::ModuleRef);
}

void PeDotNet::getFieldRVA(u32 **data, const CorTables &tables, CorTable &table)
{
    table.fieldRVA.rva = REDasm::readpointer<u32>(data);
    table.fieldRVA.field = PeDotNet::getTableIdx(data, tables, CorMetadataTables::FieldDef);
}

void PeDotNet::getAssembly(u32 **data, const CorTables &tables, CorTable &table)
{
    table.assembly.hashAlgId = REDasm::readpointer<u32>(data);
    table.assembly.major = REDasm::readpointer<u16>(data);
    table.assembly.minor = REDasm::readpointer<u16>(data);
    table.assembly.build = REDasm::readpointer<u16>(data);
    table.assembly.revision = REDasm::readpointer<u16>(data);
    table.assembly.flags = REDasm::readpointer<u32>(data);
    table.assembly.publicKey = PeDotNet::getBlobIdx(data, tables);
    table.assembly.name = PeDotNet::getStringIdx(data, tables);
    table.assembly.culture = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getAssemblyProcessor(u32 **data, const CorTables &tables, CorTable &table)
{
    RE_UNUSED(tables);

    table.assemblyProcessor.processor = REDasm::readpointer<u32>(data);
}

void PeDotNet::getAssemblyOS(u32 **data, const CorTables &tables, CorTable &table)
{
    RE_UNUSED(tables);
    RE_UNUSED(table);

    table.assemblyOS.platformId = REDasm::readpointer<u32>(data);
    table.assemblyOS.major = REDasm::readpointer<u32>(data);
    table.assemblyOS.minor = REDasm::readpointer<u32>(data);
}

void PeDotNet::getAssemblyRef(u32 **data, const CorTables &tables, CorTable &table)
{
    table.assemblyRef.major = REDasm::readpointer<u16>(data);
    table.assemblyRef.minor = REDasm::readpointer<u16>(data);
    table.assemblyRef.build = REDasm::readpointer<u16>(data);
    table.assemblyRef.revision = REDasm::readpointer<u16>(data);
    table.assemblyRef.flags = REDasm::readpointer<u32>(data);
    table.assemblyRef.flags = REDasm::readpointer<u32>(data);
    table.assemblyRef.publicKeyOrToken = PeDotNet::getBlobIdx(data, tables);
    table.assemblyRef.name = PeDotNet::getStringIdx(data, tables);
    table.assemblyRef.culture = PeDotNet::getStringIdx(data, tables);
    table.assemblyRef.hashValue = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getAssemblyRefProcessor(u32 **data, const CorTables &tables, CorTable &table)
{
    table.assemblyRefProcessor.processor = REDasm::readpointer<u32>(data);
    table.assemblyRefProcessor.assemblyRef = PeDotNet::getTableIdx(data, tables, CorMetadataTables::AssemblyRef);
}

void PeDotNet::getAssemblyRefOS(u32 **data, const CorTables &tables, CorTable &table)
{
    table.assemblyRefOS.platformId = REDasm::readpointer<u32>(data);
    table.assemblyRefOS.major = REDasm::readpointer<u32>(data);
    table.assemblyRefOS.minor = REDasm::readpointer<u32>(data);
    table.assemblyRefOS.assemblyRef = PeDotNet::getTableIdx(data, tables, CorMetadataTables::AssemblyRef);
}

void PeDotNet::getFile(u32 **data, const CorTables &tables, CorTable &table)
{
    table.file.flags = REDasm::readpointer<u32>(data);
    table.file.name = PeDotNet::getStringIdx(data, tables);
    table.file.hashValue = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getExportedType(u32 **data, const CorTables &tables, CorTable &table)
{
    table.exportedType.flags = REDasm::readpointer<u32>(data);
    table.exportedType.typeDefId = REDasm::readpointer<u32>(data);
    table.exportedType.typeName = PeDotNet::getStringIdx(data, tables);
    table.exportedType.typeNamespace = PeDotNet::getStringIdx(data, tables);

    PeDotNet::getTaggedField(data, table.exportedType.implementation, table.exportedType.implementation_tag, 2, tables,
                            { CorMetadataTables::File, CorMetadataTables::AssemblyRef, CorMetadataTables::ExportedType });
}

void PeDotNet::getManifestResource(u32 **data, const CorTables &tables, CorTable &table)
{
    table.manifestResource.offset = REDasm::readpointer<u32>(data);
    table.manifestResource.flags = REDasm::readpointer<u32>(data);
    table.manifestResource.name = PeDotNet::getStringIdx(data, tables);

    PeDotNet::getTaggedField(data, table.manifestResource.implementation, table.manifestResource.implementation_tag, 2, tables,
                            { CorMetadataTables::File, CorMetadataTables::AssemblyRef, CorMetadataTables::ExportedType });
}

void PeDotNet::getNestedClass(u32 **data, const CorTables &tables, CorTable &table)
{
    table.nestedClass.nestedClass = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);
    table.nestedClass.enclosingClass = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);
}

void PeDotNet::getGenericParam(u32 **data, const CorTables &tables, CorTable &table)
{
    table.genericParam.number = REDasm::readpointer<u16>(data);
    table.genericParam.flags = REDasm::readpointer<u16>(data);

    PeDotNet::getTaggedField(data, table.genericParam.owner, table.genericParam.owner_tag, 2, tables,
                            {CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::TypeSpec });

    table.genericParam.name = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getGenericParamConstraint(u32 **data, const CorTables &tables, CorTable &table)
{
    table.genericParamConstraint.owner = PeDotNet::getTableIdx(data, tables, CorMetadataTables::GenericParam);

    PeDotNet::getTaggedField(data, table.genericParamConstraint.constraint, table.genericParamConstraint.constraint_tag, 2, tables,
                            {CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::TypeSpec });
}

void PeDotNet::getTaggedField(u32** data, u32 &value, u8 &tag, u8 tagbits, const CorTables &tables, const std::list<u32> &tablerefs)
{
    u32 mask = 0;

    for(u32 i = 0 ; i < tagbits; i++)
        mask |= (1u << i);

    u16 maxvalue = (0xFFFF & static_cast<u16>(mask)) >> tagbits;
    u32 tagvalue = 0, maxrows = PeDotNet::maxRows(tables, tablerefs);

    if(maxrows > maxvalue) // 32-bit is needed
        tagvalue = REDasm::readpointer<u32>(data);
    else
        tagvalue = REDasm::readpointer<u16>(data);

    value = tagvalue >> tagbits;
    tag = tagvalue & mask;
}

u32 PeDotNet::maxRows(const CorTables &tables, const std::list<u32> &tablerefs)
{
    u32 res = 0;

    std::for_each(tablerefs.begin(), tablerefs.begin(), [tables, &res](u32 table) {
        res = std::max(res, tables.rows.at(table));
    });

    return res;
}

} // namespace REDasm
