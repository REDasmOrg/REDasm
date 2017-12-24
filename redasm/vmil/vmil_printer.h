#ifndef VMIL_PRINTER_H
#define VMIL_PRINTER_H

#include "../plugins/processor/printer.h"
#include "vmil_types.h"

namespace REDasm {
namespace VMIL {

class VMILPrinter: public Printer
{
    public:
        VMILPrinter(const PrinterPtr& srcprinter, DisassemblerFunctions* disassembler, SymbolTable* symboltable);
        virtual std::string reg(const RegisterOperand& regop) const;

    private:
        const PrinterPtr& _srcprinter;
};

typedef std::shared_ptr<VMILPrinter> VMILPrinterPtr;

} // namespace VMIL
} // namespace REDasm

#endif // VMIL_PRINTER_H
