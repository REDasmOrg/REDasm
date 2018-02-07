#ifndef DOTNET_READER_H
#define DOTNET_READER_H

#include "dotnet_header.h"
#include "dotnet_tables.h"

namespace REDasm {

class DotNetReader
{
    private:
        typedef std::function<void(u32, const std::string&)> MethodCallback;
        typedef std::function<u32(const CorTable&)> IndexCallback;

    public:
        DotNetReader(ImageCor20MetaData *cormetadata);
        void iterateTypes(MethodCallback cbmethods) const;
        bool isValid() const;

    private:
        const CorTableRows& getTableRows(u32 cortable) const;
        void buildType(std::string& s, u32 stringidx) const;
        void iterateMethods(const CorTable &cortypedef, u32 methodcount, MethodCallback cbmethods) const;
        u32 getListCount(CorTableRows::const_iterator it, u32 cortable, IndexCallback cbindex) const;
        std::string getString(u32 index) const;

    private:
        ImageCor20MetaData* _cormetadata;
        ImageCor20TablesHeader* _cortablesheader;
        CorTables _cortables;
        char* _corstrings;
};

} // namespace REDasm

#endif // DOTNETREADER_H
