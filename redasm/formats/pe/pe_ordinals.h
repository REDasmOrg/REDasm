#ifndef PE_ORDINALS_TYPES_H
#define PE_ORDINALS_TYPES_H

#include "../../redasm.h"

#define LOAD_ORDINALS(dll, jsonfile) { _libraries[dll] = OrdinalMap(); \
                                     PEOrdinals::compile(#jsonfile, _libraries[dll]); }

namespace REDasm {
typedef std::map<u16, std::string> OrdinalMap;
typedef std::map<std::string, OrdinalMap> ResolveMap;

class PEOrdinals
{
    private:
        PEOrdinals();

    public:
        static void compile(const std::string& jsonfile, OrdinalMap& m);
};

}

#endif // PE_ORDINALS_TYPES_H
