#ifndef METAARM_PRINTER_H
#define METAARM_PRINTER_H

#include "../../plugins/assembler/printer.h"

namespace REDasm {

class MetaARMPrinter: public CapstonePrinter
{
    public:
        MetaARMPrinter(csh cshandle, DisassemblerAPI* disassembler);

    public:
        virtual std::string size(const Operand& operand) const;
        virtual std::string mem(const Operand& operand) const;
};

} // namespace REDasm

#endif // METAARM_PRINTER_H
