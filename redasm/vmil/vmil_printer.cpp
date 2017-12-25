#include "vmil_printer.h"

namespace REDasm {
namespace VMIL {

VMILPrinter::VMILPrinter(const PrinterPtr &srcprinter, DisassemblerFunctions *disassembler, SymbolTable *symboltable): Printer(disassembler, symboltable), _srcprinter(srcprinter)
{

}

std::string VMILPrinter::reg(const RegisterOperand &regop) const
{
    if(regop.type == VMIL_REG_OPERAND)
        return "$vreg" + std::to_string(regop.r);

    return this->_srcprinter->reg(regop);
}

} // namespace VMIL
} // namespace REDasm
