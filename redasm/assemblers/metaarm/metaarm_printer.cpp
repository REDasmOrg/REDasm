#include "metaarm_printer.h"

namespace REDasm {

MetaARMPrinter::MetaARMPrinter(csh cshandle, DisassemblerAPI *disassembler): CapstonePrinter(cshandle, disassembler) { }
std::string MetaARMPrinter::size(const Operand &operand) const { return std::string(); }

} // namespace REDasm
