#include "dotnet_reader.h"
#include "dotnet.h"

#define IS_STREAM_VALID(s) (s && s->Offset)

namespace REDasm {

DotNetReader::DotNetReader(ImageCor20MetaData *cormetadata): m_cormetadata(cormetadata), m_cortablesheader(NULL)
{
    REDasm::log(".NET Version: " + PeDotNet::getVersion(cormetadata));
    ImageStreamHeader* streamheader = PeDotNet::getStream(cormetadata, "#~");

    if(!IS_STREAM_VALID(streamheader))
        return;

    m_cortablesheader = REDasm::relpointer<ImageCor20TablesHeader>(cormetadata, streamheader->Offset);
    PeDotNet::getTables(m_cortablesheader, m_cortables);

    streamheader = PeDotNet::getStream(cormetadata, "#Strings");

    if(!IS_STREAM_VALID(streamheader))
        return;

    m_corstrings = REDasm::relpointer<char>(cormetadata, streamheader->Offset);
}

void DotNetReader::iterateTypes(MethodCallback cbmethods) const
{
    const CorTableRows& cortdrows = this->getTableRows(CorMetadataTables::TypeDef);
    const CorTableRows& cormdrows = this->getTableRows(CorMetadataTables::MethodDef);

    for(auto it = cortdrows.begin(); it != cortdrows.end(); it++)
    {
        u32 c = this->getListCount(it, cortdrows, cormdrows.size(), [](const CorTablePtr& cortable) -> u32 {
            return cortable->typeDef.methodList;
        });

        this->iterateMethods(*it, c, cbmethods);
    }
}

bool DotNetReader::isValid() const
{
    ImageStreamHeader* streamheader = PeDotNet::getStream(m_cormetadata, "#~");

    if(!streamheader || !streamheader->Offset)
        return false;

    return true;
}

const CorTableRows &DotNetReader::getTableRows(u32 cortable) const { return m_cortables.items.at(cortable); }

void DotNetReader::buildType(std::string &dest, u32 stringidx) const
{
    std::string s = this->getString(stringidx);

    if(s.front() != '.' && !dest.empty() && (dest.back() != '.'))
        dest += ".";

    dest += s;
}

void DotNetReader::iterateMethods(const CorTablePtr& cortypedef, u32 methodcount, MethodCallback cbmethods) const
{
    std::string tname;

    if(cortypedef->typeDef.typeNamespace)
        this->buildType(tname, cortypedef->typeDef.typeNamespace);

    this->buildType(tname, cortypedef->typeDef.typeName);

    const CorTableRows& cormdrows = this->getTableRows(CorMetadataTables::MethodDef);
    auto it = cormdrows.begin();
    std::advance(it, DOTNET_INDEX(cortypedef->typeDef.methodList));

    for(u32 i = 0; (it != cormdrows.end()) && (i < methodcount); it++, i++)
    {
        std::string mname = tname;
        this->buildType(mname, (*it)->methodDef.name);
        cbmethods((*it)->methodDef.rva, mname + "()");
    }
}

u32 DotNetReader::getListCount(CorTableRows::const_iterator rowsit, const CorTableRows& cortablerows, u32 maxrows, IndexCallback cbindex) const
{
    u32 index = cbindex(*rowsit), lastindex = 0;
    rowsit++;

    if(rowsit != cortablerows.end())
        lastindex = std::min(maxrows, cbindex(*rowsit));
    else
        lastindex = maxrows;

    return lastindex - index;
}

std::string DotNetReader::getString(u32 index) const
{
    if(!index)
        return "string_null";

    if(!m_corstrings)
        return "string_" + std::to_string(index);

    return m_corstrings + index;
}

} // namespace REDasm
