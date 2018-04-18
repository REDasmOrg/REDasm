#ifndef METAARM_PRINTER_H
#define METAARM_PRINTER_H

#include "../../plugins/assembler/printer.h"

namespace REDasm {

class MetaARMPrinter: public CapstonePrinter
{
    public:
        MetaARMPrinter(csh cshandle, DisassemblerAPI* disassembler, SymbolTable* symboltable);
        virtual std::string ptr(const std::string &expr) const;
};

} // namespace REDasm

#endif // METAARM_PRINTER_H
