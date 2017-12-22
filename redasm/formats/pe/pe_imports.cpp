#include "pe_imports.h"

namespace REDasm {

ResolveMap PEImports::_libraries;

PEImports::PEImports()
{

}

void PEImports::loadImport(std::string dllname)
{
    if(_libraries.find(dllname) != _libraries.end())
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
    auto lit = _libraries.find(dllname);

    if(lit != _libraries.end())
    {
        OrdinalMap& ordinalmap = lit->second;
        auto oit = ordinalmap.find(ordinal);

        if(oit == ordinalmap.end())
            return false;

        name = oit->second;
        return true;
    }

    return false;
}

} // namespace REDasm
