#include "coff_symboltable.h"
#include <iostream>
#include "../../plugins/format.h"

#define	COFF_ENTRYSIZE    18
#define	COFF_AUXENTRYSIZE 18
#define COFF_NEXTENTRY(symentry) reinterpret_cast<COFF_Entry*>(reinterpret_cast<u8*>(symentry) + COFF_ENTRYSIZE + (symentry->e_numaux * COFF_AUXENTRYSIZE))

namespace REDasm {
namespace COFF {

SymbolTable::SymbolTable(u8 *symdata, u64 count): m_count(count), m_symdata(symdata)
{
    m_stringtable = reinterpret_cast<char*>(m_symdata + (count * COFF_ENTRYSIZE));
}

void SymbolTable::read(SymbolCallback symbolcb)
{
    COFF_Entry* entry = reinterpret_cast<COFF_Entry*>(m_symdata);
    std::string name;

    // All needed info for disassemblers & symbol tables: http://wiki.osdev.org/COFF#Symbol_Table
    while(reinterpret_cast<size_t*>(entry) < reinterpret_cast<size_t*>(m_stringtable))
    {
        if(entry->e_value && (entry->e_scnum > 0) && ((entry->e_sclass == C_EXT) || (entry->e_sclass == C_STAT)))
        {
            if(!entry->e_zeroes)
                name = this->nameFromTable(entry->e_offset);
            else
                name = std::string(reinterpret_cast<const char*>(&entry->e_name));

            if(!name.empty())
                symbolcb(name, entry);
        }

        entry = COFF_NEXTENTRY(entry);
    }
}

std::string SymbolTable::nameFromTable(u64 offset) const
{
    return std::string(reinterpret_cast<const char*>(m_stringtable + offset));
}

void loadSymbols(SymbolCallback symbolcb, u8 *symdata, u64 count)
{
    SymbolTable symtable(symdata, count);
    symtable.read(symbolcb);
}

} // namespace COFF
} // namespace REDasm
