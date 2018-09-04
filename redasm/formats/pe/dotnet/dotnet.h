#ifndef PEDOTNET_H
#define PEDOTNET_H

#define DOTNET_INDEX(i) (i - 1)

#include "dotnet_header.h"
#include "dotnet_tables.h"

namespace REDasm {

class PeDotNet
{
    private:
        typedef std::function<void(u32**, const CorTables&, CorTablePtr&)> TableCallback;
        typedef std::unordered_map<u32, TableCallback> TableDispatcher;

    private:
        PeDotNet();

    public:
        static std::string getVersion(ImageCor20MetaData *cormetadata);
        static u16 getNumberOfStreams(ImageCor20MetaData* cormetadata);
        static ImageStreamHeader* getStream(ImageCor20MetaData* cormetadata, const std::string &id);
        static bool getTables(ImageCor20TablesHeader* cortablesheader, CorTables& tables);

    private:
        static u32 getSizeOfHeap(ImageCor20TablesHeader *cortablesheader, u32 bitno);
        static u32 getValueIdx(u32** data, u32 offsize);
        static u32 getTableIdx(u32** data, const CorTables& tables, u32 table);
        static u32 getStringIdx(u32** data, const CorTables& tables);
        static u32 getGuidIdx(u32** data, const CorTables& tables);
        static u32 getBlobIdx(u32** data, const CorTables& tables);
        static void getModule(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getTypeRef(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getTypeDef(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getFieldDef(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getMethodDef(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getParamDef(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getInterfaceImpl(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getMemberRef(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getConstant(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getCustomAttribute(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getFieldMarshal(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getDeclSecurity(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getClassLayout(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getFieldLayout(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getStandaloneSig(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getEventMap(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getEvent(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getPropertyMap(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getProperty(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getMethodSemantics(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getMethodImpl(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getModuleRef(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getTypeSpec(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getImplMap(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getFieldRVA(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getAssembly(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getAssemblyProcessor(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getAssemblyOS(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getAssemblyRef(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getAssemblyRefProcessor(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getAssemblyRefOS(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getFile(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getExportedType(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getManifestResource(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getNestedClass(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getGenericParam(u32** data, const CorTables& tables, CorTablePtr& table);
        static void getGenericParamConstraint(u32** data, const CorTables& tables, CorTablePtr& table);
        static void initTables();

    private:
        template<u32 S> static void getTaggedField(u32** data, u32& value, u8& tag, u8 tagbits, const CorTables& tables, const std::array<u32, S>& tablerefs);
        template<u32 S> static u32 maxRows(const CorTables& tables, const std::array<u32, S>& tablerefs);

    private:
        static std::list<u32> m_tables;
        static TableDispatcher m_dispatcher;
};

template<u32 S> void PeDotNet::getTaggedField(u32** data, u32& value, u8& tag, u8 tagbits, const CorTables& tables, const std::array<u32, S>& tablerefs)
{
    u32 mask = 0;

    for(u32 i = 0 ; i < tagbits; i++)
        mask |= (1u << i);

    u16 maxvalue = (static_cast<u16>(0xFFFF) & ~static_cast<u16>(mask)) >> tagbits;
    u32 tagvalue = 0, maxrows = PeDotNet::maxRows<S>(tables, tablerefs);

    if(maxrows > maxvalue) // 32-bit is needed
        tagvalue = REDasm::readpointer<u32>(data);
    else
        tagvalue = REDasm::readpointer<u16>(data);

    value = tagvalue >> tagbits;
    tag = tagvalue & mask;
}

template<u32 S> u32 PeDotNet::maxRows(const CorTables& tables, const std::array<u32, S>& tablerefs)
{
    u32 res = 0;

    std::for_each(tablerefs.begin(), tablerefs.end(), [&tables, &res](u32 table) {
        auto it = tables.rows.find(table);

        if(it != tables.rows.end())
            res = std::max(res, it->second);
    });

    return res;
}

} // namespace REDasm

#endif // PEDOTNET_H
