#include "dotnet.h"
#include <cstring>
#include <iostream>

#define PUSH_TABLE(t) m_tables.push_back(CorMetadataTables::t); \
                      m_dispatcher[CorMetadataTables::t] = &PeDotNet::get##t

#define GET_TAGGED_FIELD(S, data, field, tagbits, tables, ...) PeDotNet::getTaggedField(data, field, field##_tag, tagbits, tables, __VA_ARGS__)

namespace REDasm {

std::list<u32> PeDotNet::m_tables;
PeDotNet::TableDispatcher PeDotNet::m_dispatcher;

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
            tables.items[i] = CorTableRows();
            tables.items[i].reserve(*tabledata);
            tabledata++;
        }
    }

    // Read columns
    for(auto rit = tables.rows.begin(); rit != tables.rows.end(); rit++)
    {
        auto it = m_dispatcher.find(rit->first);

        if(it == m_dispatcher.end())
        {
            REDasm::log("Cannot find table " + REDasm::quoted(rit->first));
            return false;
        }

        CorTableRows& rows = tables.items[rit->first];

        for(u32 i = 0; i < rit->second; i++)
        {
            CorTablePtr table = std::make_unique<CorTable>();
            it->second(&tabledata, tables, table);
            rows.push_back(std::move(table));
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
    if(!m_tables.empty())
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

void PeDotNet::getTaggedField(u32 **data, u32 &value, u8 &tag, u8 tagbits, const CorTables &tables, const std::list<u32> &tablerefs)
{
    u32 mask = 0;

    for(u32 i = 0 ; i < tagbits; i++)
        mask |= (1u << i);

    u16 maxvalue = (static_cast<u16>(0xFFFF) & ~static_cast<u16>(mask)) >> tagbits;
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

    for(u32 table : tablerefs)
    {
        auto it = tables.rows.find(table);

        if(it != tables.rows.end())
            res = std::max(res, it->second);
    }

    return res;
}

void PeDotNet::getModule(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->module.generation = REDasm::readpointer<u16>(data);
    table->module.name = PeDotNet::getStringIdx(data, tables);
    table->module.mvId = PeDotNet::getGuidIdx(data, tables);
    table->module.encId = PeDotNet::getGuidIdx(data, tables);
    table->module.encBaseId = PeDotNet::getGuidIdx(data, tables);
}

void PeDotNet::getTypeRef(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    GET_TAGGED_FIELD(4, data, table->typeRef.resolutionScope, 2, tables,
    { CorMetadataTables::Module, CorMetadataTables::ModuleRef, CorMetadataTables::Assembly, CorMetadataTables::AssemblyRef });

    table->typeRef.typeName = PeDotNet::getStringIdx(data, tables);
    table->typeRef.typeNamespace = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getTypeDef(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->typeDef.flags = REDasm::readpointer<u32>(data);
    table->typeDef.typeName = PeDotNet::getStringIdx(data, tables);
    table->typeDef.typeNamespace = PeDotNet::getStringIdx(data, tables);

    GET_TAGGED_FIELD(3, data, table->typeDef.extends, 2, tables,
                     { CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::TypeSpec });

    table->typeDef.fieldList = PeDotNet::getTableIdx(data, tables, CorMetadataTables::FieldDef);
    table->typeDef.methodList = PeDotNet::getTableIdx(data, tables, CorMetadataTables::MethodDef);
}

void PeDotNet::getFieldDef(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->fieldDef.flags = REDasm::readpointer<u16>(data);
    table->fieldDef.name = PeDotNet::getStringIdx(data, tables);
    table->fieldDef.signature = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getMethodDef(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->methodDef.rva = REDasm::readpointer<u32>(data);
    table->methodDef.implFlags = REDasm::readpointer<u16>(data);
    table->methodDef.flags = REDasm::readpointer<u16>(data);
    table->methodDef.name = PeDotNet::getStringIdx(data, tables);
    table->methodDef.signature = PeDotNet::getBlobIdx(data, tables);
    table->methodDef.paramList = PeDotNet::getTableIdx(data, tables, CorMetadataTables::ParamDef);
}

void PeDotNet::getParamDef(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->paramDef.flags = REDasm::readpointer<u16>(data);
    table->paramDef.sequence = REDasm::readpointer<u16>(data);
    table->paramDef.name = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getInterfaceImpl(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->interfaceImpl.classIdx = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);

    GET_TAGGED_FIELD(3, data, table->interfaceImpl.interfaceIdx, 2, tables,
                     { CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::TypeSpec });
}

void PeDotNet::getMemberRef(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    GET_TAGGED_FIELD(5, data, table->memberRef.classIdx, 2, tables,
                     {CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::ModuleRef,
                      CorMetadataTables::MethodDef, CorMetadataTables::TypeSpec });

    table->memberRef.name = PeDotNet::getStringIdx(data, tables);
    table->memberRef.signature = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getConstant(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->constant.type = REDasm::readpointer<u16>(data);

    GET_TAGGED_FIELD(3, data, table->constant.parent, 2, tables,
                     { CorMetadataTables::FieldDef, CorMetadataTables::ParamDef, CorMetadataTables::Property });

    table->constant.value = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getCustomAttribute(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    GET_TAGGED_FIELD(18, data, table->customAttribute.parent, 5, tables,
                     { CorMetadataTables::MethodDef, CorMetadataTables::FieldDef, CorMetadataTables::TypeRef,
                       CorMetadataTables::TypeDef, CorMetadataTables::ParamDef, CorMetadataTables::InterfaceImpl,
                       CorMetadataTables::MemberRef, CorMetadataTables::Module, /* CorMetaDataTables::Permission, */
                       CorMetadataTables::Property, CorMetadataTables::Event, CorMetadataTables::StandaloneSig,
                       CorMetadataTables::ModuleRef, CorMetadataTables::TypeSpec, CorMetadataTables::Assembly,
                       CorMetadataTables::AssemblyRef, CorMetadataTables::File, CorMetadataTables::ExportedType,
                       CorMetadataTables::ManifestResource });

    GET_TAGGED_FIELD(2, data, table->customAttribute.type, 3, tables,
                     { CorMetadataTables::MethodDef, CorMetadataTables::MemberRef });

    table->customAttribute.value = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getFieldMarshal(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    GET_TAGGED_FIELD(2, data, table->fieldMarshal.parent, 1, tables,
                     { CorMetadataTables::FieldDef, CorMetadataTables::ParamDef });

    table->fieldMarshal.nativeType = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getDeclSecurity(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->declSecurity.action = REDasm::readpointer<u16>(data);

    GET_TAGGED_FIELD(3, data, table->declSecurity.parent, 2, tables,
                     { CorMetadataTables::TypeDef, CorMetadataTables::MethodDef, CorMetadataTables::Assembly });

    table->declSecurity.permissionSet = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getClassLayout(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->classLayout.packingSize = REDasm::readpointer<u16>(data);
    table->classLayout.classSize = REDasm::readpointer<u32>(data);
    table->classLayout.parent = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);
}

void PeDotNet::getFieldLayout(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->fieldLayout.offset = REDasm::readpointer<u32>(data);
    table->fieldLayout.field = PeDotNet::getTableIdx(data, tables, CorMetadataTables::FieldDef);
}

void PeDotNet::getStandaloneSig(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->standaloneSig.signature = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getEventMap(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->eventMap.parent = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);
    table->eventMap.eventList = PeDotNet::getTableIdx(data, tables, CorMetadataTables::Event);
}

void PeDotNet::getEvent(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->event.eventFlags = REDasm::readpointer<u16>(data);
    table->event.name = PeDotNet::getStringIdx(data, tables);

    GET_TAGGED_FIELD(3, data, table->event.eventType, 2, tables,
                     { CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::TypeSpec });
}

void PeDotNet::getPropertyMap(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->propertyMap.parent = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);
    table->propertyMap.propertyList = PeDotNet::getTableIdx(data, tables, CorMetadataTables::Property);
}

void PeDotNet::getProperty(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->property.flags = REDasm::readpointer<u16>(data);
    table->property.name = PeDotNet::getStringIdx(data, tables);
    table->property.type = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getMethodSemantics(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->methodSemantics.semantics = REDasm::readpointer<u16>(data);
    table->methodSemantics.method = PeDotNet::getTableIdx(data, tables, CorMetadataTables::MethodDef);

    GET_TAGGED_FIELD(2, data, table->methodSemantics.association, 1, tables,
                     { CorMetadataTables::Event, CorMetadataTables::Property });
}

void PeDotNet::getMethodImpl(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->methodImpl.classIdx = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);

    GET_TAGGED_FIELD(2, data, table->methodImpl.methodBody, 1, tables,
                     { CorMetadataTables::MethodDef, CorMetadataTables::MemberRef});

    GET_TAGGED_FIELD(2, data, table->methodImpl.methodDeclaration, 1, tables,
                     { CorMetadataTables::MethodDef, CorMetadataTables::MemberRef});
}

void PeDotNet::getModuleRef(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->moduleRef.name = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getTypeSpec(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->typeSpec.signature = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getImplMap(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->implMap.mappingFlags = REDasm::readpointer<u16>(data);

    GET_TAGGED_FIELD(2, data, table->implMap.memberForwarded, 1, tables,
                     { CorMetadataTables::FieldDef, CorMetadataTables::MethodDef });

    table->implMap.importName = PeDotNet::getStringIdx(data, tables);
    table->implMap.importScope = PeDotNet::getTableIdx(data, tables, CorMetadataTables::ModuleRef);
}

void PeDotNet::getFieldRVA(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->fieldRVA.rva = REDasm::readpointer<u32>(data);
    table->fieldRVA.field = PeDotNet::getTableIdx(data, tables, CorMetadataTables::FieldDef);
}

void PeDotNet::getAssembly(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->assembly.hashAlgId = REDasm::readpointer<u32>(data);
    table->assembly.major = REDasm::readpointer<u16>(data);
    table->assembly.minor = REDasm::readpointer<u16>(data);
    table->assembly.build = REDasm::readpointer<u16>(data);
    table->assembly.revision = REDasm::readpointer<u16>(data);
    table->assembly.flags = REDasm::readpointer<u32>(data);
    table->assembly.publicKey = PeDotNet::getBlobIdx(data, tables);
    table->assembly.name = PeDotNet::getStringIdx(data, tables);
    table->assembly.culture = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getAssemblyProcessor(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    RE_UNUSED(tables);

    table->assemblyProcessor.processor = REDasm::readpointer<u32>(data);
}

void PeDotNet::getAssemblyOS(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    RE_UNUSED(tables);
    RE_UNUSED(table);

    table->assemblyOS.platformId = REDasm::readpointer<u32>(data);
    table->assemblyOS.major = REDasm::readpointer<u32>(data);
    table->assemblyOS.minor = REDasm::readpointer<u32>(data);
}

void PeDotNet::getAssemblyRef(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->assemblyRef.major = REDasm::readpointer<u16>(data);
    table->assemblyRef.minor = REDasm::readpointer<u16>(data);
    table->assemblyRef.build = REDasm::readpointer<u16>(data);
    table->assemblyRef.revision = REDasm::readpointer<u16>(data);
    table->assemblyRef.flags = REDasm::readpointer<u32>(data);
    table->assemblyRef.flags = REDasm::readpointer<u32>(data);
    table->assemblyRef.publicKeyOrToken = PeDotNet::getBlobIdx(data, tables);
    table->assemblyRef.name = PeDotNet::getStringIdx(data, tables);
    table->assemblyRef.culture = PeDotNet::getStringIdx(data, tables);
    table->assemblyRef.hashValue = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getAssemblyRefProcessor(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->assemblyRefProcessor.processor = REDasm::readpointer<u32>(data);
    table->assemblyRefProcessor.assemblyRef = PeDotNet::getTableIdx(data, tables, CorMetadataTables::AssemblyRef);
}

void PeDotNet::getAssemblyRefOS(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->assemblyRefOS.platformId = REDasm::readpointer<u32>(data);
    table->assemblyRefOS.major = REDasm::readpointer<u32>(data);
    table->assemblyRefOS.minor = REDasm::readpointer<u32>(data);
    table->assemblyRefOS.assemblyRef = PeDotNet::getTableIdx(data, tables, CorMetadataTables::AssemblyRef);
}

void PeDotNet::getFile(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->file.flags = REDasm::readpointer<u32>(data);
    table->file.name = PeDotNet::getStringIdx(data, tables);
    table->file.hashValue = PeDotNet::getBlobIdx(data, tables);
}

void PeDotNet::getExportedType(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->exportedType.flags = REDasm::readpointer<u32>(data);
    table->exportedType.typeDefId = REDasm::readpointer<u32>(data);
    table->exportedType.typeName = PeDotNet::getStringIdx(data, tables);
    table->exportedType.typeNamespace = PeDotNet::getStringIdx(data, tables);

    GET_TAGGED_FIELD(3, data, table->exportedType.implementation, 2, tables,
                     { CorMetadataTables::File, CorMetadataTables::AssemblyRef, CorMetadataTables::ExportedType });
}

void PeDotNet::getManifestResource(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->manifestResource.offset = REDasm::readpointer<u32>(data);
    table->manifestResource.flags = REDasm::readpointer<u32>(data);
    table->manifestResource.name = PeDotNet::getStringIdx(data, tables);

    GET_TAGGED_FIELD(3, data, table->manifestResource.implementation, 2, tables,
                     { CorMetadataTables::File, CorMetadataTables::AssemblyRef, CorMetadataTables::ExportedType });
}

void PeDotNet::getNestedClass(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->nestedClass.nestedClass = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);
    table->nestedClass.enclosingClass = PeDotNet::getTableIdx(data, tables, CorMetadataTables::TypeDef);
}

void PeDotNet::getGenericParam(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->genericParam.number = REDasm::readpointer<u16>(data);
    table->genericParam.flags = REDasm::readpointer<u16>(data);

    GET_TAGGED_FIELD(3, data, table->genericParam.owner, 2, tables,
                     { CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::TypeSpec });

    table->genericParam.name = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getGenericParamConstraint(u32 **data, const CorTables &tables, CorTablePtr &table)
{
    table->genericParamConstraint.owner = PeDotNet::getTableIdx(data, tables, CorMetadataTables::GenericParam);

    GET_TAGGED_FIELD(3, data, table->genericParamConstraint.constraint, 2, tables,
                     { CorMetadataTables::TypeDef, CorMetadataTables::TypeRef, CorMetadataTables::TypeSpec });
}

} // namespace REDasm
