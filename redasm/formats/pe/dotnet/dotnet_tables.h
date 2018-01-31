#ifndef DOTNET_TABLES_H
#define DOTNET_TABLES_H

#include "../../../redasm.h"

namespace REDasm {

struct CorTable
{
    union { u32 generation, resolutionScope; };
    union { u32 name, typeName; };
    union { u32 mvId, typeNamespace; };

    u32 encId, encBaseId;
};

typedef std::list<CorTable> CorTableList;

struct CorTables
{
    u8 stringoffsize, guidoffsize, bloboffsize;

    std::map<u32, CorTableList> items;
    std::map<u32, u32> rows;
};

} // namespace REDasm

#endif // DOTNET_TABLES_H
