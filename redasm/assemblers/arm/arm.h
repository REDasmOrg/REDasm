#ifndef ARM_H
#define ARM_H

#include "../../plugins/plugins.h"
#include "arm_printer.h"

namespace REDasm {

class ARMAssembler: public CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_ARM>
{
    public:
        ARMAssembler();
        virtual const char* name() const;
        virtual bool decode(Buffer buffer, const InstructionPtr &instruction);
        virtual Printer* createPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable) const { return new ARMPrinter(this->_cshandle, disassembler, symboltable); }

    private:
        bool isPC(register_t reg) const;
        void analyzeInstruction(const InstructionPtr& instruction, cs_insn* insn) const;
};

DECLARE_ASSEMBLER_PLUGIN(ARMAssembler, arm)

} // namespace REDasm

#endif // ARM_H
