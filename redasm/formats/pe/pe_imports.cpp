#include "pe_imports.h"

#define LOAD_ORDINALS(dll, jsonfile) { m_libraries[dll] = OrdinalsMap(); \
                                     REDasm::loadordinals(REDasm::makeFormatPath("pe", #jsonfile".json"), m_libraries[dll]); }

namespace REDasm {

PEImports::ResolveMap PEImports::m_libraries;

PEImports::PEImports()
{

}

void PEImports::loadImport(std::string dllname)
{
    if(m_libraries.find(dllname) != m_libraries.end())
        return;

    if(dllname.find("msvbvm60") != std::string::npos)
        LOAD_ORDINALS(dllname, msvbvm60)
    else if(dllname.find("msvbvm50") != std::string::npos)
        LOAD_ORDINALS(dllname, msvbvm50)
    else if(dllname.find("mfc70u") != std::string::npos)
        LOAD_ORDINALS(dllname, mfc70u)
    else if(dllname.find("mfc71u") != std::string::npos)
        LOAD_ORDINALS(dllname, mfc71u)
    else if(dllname.find("mfc71") != std::string::npos)
        LOAD_ORDINALS(dllname, mfc71)
}

bool PEImports::importName(const std::string &dllname, u16 ordinal, std::string &name)
{
    PEImports::loadImport(dllname);

    auto it = m_libraries.find(dllname);

    if(it == m_libraries.end())
        return false;

    name = REDasm::ordinal(it->second, ordinal);
    return true;
}

} // namespace REDasm
