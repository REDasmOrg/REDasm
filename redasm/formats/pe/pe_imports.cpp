#include "pe_imports.h"
#include "ordinals/msvbvm.h"
#include <fstream>

namespace REDasm {

ResolveMap PEImports::_libraries;

PEImports::PEImports()
{

}

void PEImports::loadImport(std::string dllname)
{
    if(_libraries.find(dllname) != _libraries.end())
        return;

    if(dllname.find("msvbvm") != std::string::npos)
        COMPILE_MAP(dllname, MSVBVM);
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
