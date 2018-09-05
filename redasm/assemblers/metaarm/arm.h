#ifndef ARM_H
#define ARM_H

#include "../../plugins/plugins.h"
#include "metaarm_printer.h"

namespace REDasm {

class ARMAssembler: public CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_ARM>
{
    public:
        ARMAssembler();
        virtual const char* name() const;
        virtual u32 flags() const;
        virtual bool decode(Buffer buffer, const InstructionPtr &instruction);
        virtual VMIL::Emulator* createEmulator(DisassemblerAPI *disassembler) const;
        virtual Printer* createPrinter(DisassemblerAPI *disassembler) const;
};

DECLARE_ASSEMBLER_PLUGIN(ARMAssembler, arm)

} // namespace REDasm

#endif // ARM_H
