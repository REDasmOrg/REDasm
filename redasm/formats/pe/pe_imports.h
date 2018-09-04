#ifndef PE_IMPORTS_H
#define PE_IMPORTS_H

#include <unordered_map>
#include <string>
#include "../../redasm.h"
#include "../../support/ordinals.h"

namespace REDasm {

class PEImports
{
    private:
        typedef std::map<std::string, OrdinalsMap> ResolveMap;

    private:
        PEImports();
        static void loadImport(std::string dllname);

    public:
        static bool importName(const std::string& dllname, u16 ordinal, std::string& name);

    private:
        static ResolveMap m_libraries;
};

} // namespace REDasm

#endif // PE_IMPORTS_H
