#ifndef METAARM_PRINTER_H
#define METAARM_PRINTER_H

#include "../../plugins/assembler/printer.h"

namespace REDasm {

class MetaARMPrinter: public CapstonePrinter
{
    public:
        MetaARMPrinter(csh cshandle, DisassemblerAPI* disassembler, SymbolTable* symboltable);
};

} // namespace REDasm

#endif // METAARM_PRINTER_H
