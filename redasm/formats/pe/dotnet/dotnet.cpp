#include "dotnet.h"
#include <cstring>
#include <iostream>

#define TAG_MASK1 0x00000001
#define TAG_MASK2 0x00000003
#define TAG_MASK3 0x00000007
#define TAG_MASK5 0x0000001F

#define HAS_TAG(v, m, t) ((v & m) == t)
#define TAG_INDEX(v, b)  ((v & TAG_MASK##b) >> b)

//#define READ_INDEX(t) (tables.rows[CorMetaDataTables::t] > 0xFFFF)

#define PUSH_TABLE(t) _tables.push_back(CorMetaDataTables::t); \
                      _dispatcher[CorMetaDataTables::t] = &PeDotNet::get##t

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

            CorTableList tl;
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
    PUSH_TABLE(Field);
    PUSH_TABLE(MethodDef);
    PUSH_TABLE(Param);
    PUSH_TABLE(InterfaceImpl);
    PUSH_TABLE(MemberRef);
    PUSH_TABLE(Constant);
    PUSH_TABLE(CustomAttribute);
    PUSH_TABLE(FieldMarshal);
    PUSH_TABLE(DeclSecurity);
    PUSH_TABLE(ClassLayout);
    PUSH_TABLE(FieldLayout);
    PUSH_TABLE(StandaloneSig);
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
    table.generation = REDasm::readpointer<u16>(data);
    table.name = PeDotNet::getStringIdx(data, tables);
    table.mvId = PeDotNet::getGuidIdx(data, tables);
    table.encId = PeDotNet::getGuidIdx(data, tables);
    table.encBaseId = PeDotNet::getGuidIdx(data, tables);
}

void PeDotNet::getTypeRef(u32 **data, const CorTables &tables, CorTable &table)
{
    //table.resolutionScope = ???;
    table.typeName = PeDotNet::getStringIdx(data, tables);
    table.typeNamespace = PeDotNet::getStringIdx(data, tables);
}

void PeDotNet::getTypeDef(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getField(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getMethodDef(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getParam(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getInterfaceImpl(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getMemberRef(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getConstant(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getCustomAttribute(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getFieldMarshal(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getDeclSecurity(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getClassLayout(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getFieldLayout(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getStandaloneSig(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getEvent(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getPropertyMap(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getProperty(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getMethodSemantics(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getMethodImpl(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getModuleRef(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getTypeSpec(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getImplMap(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getFieldRVA(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getAssembly(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getAssemblyProcessor(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getAssemblyOS(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getAssemblyRef(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getAssemblyRefProcessor(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getAssemblyRefOS(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getFile(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getExportedType(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getManifestResource(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getNestedClass(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getGenericParam(u32 **data, const CorTables &tables, CorTable &table)
{

}

void PeDotNet::getGenericParamConstraint(u32 **data, const CorTables &tables, CorTable &table)
{

}

} // namespace REDasm
