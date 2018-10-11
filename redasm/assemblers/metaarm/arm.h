#ifndef ARM_H
#define ARM_H

#include "../../plugins/plugins.h"
#include "arm_common.h"
#include "metaarm_printer.h"

namespace REDasm {

class ARMAssembler: public ARMCommonAssembler<CS_ARCH_ARM, CS_MODE_ARM>
{
    public:
        ARMAssembler();
        virtual const char* name() const;
        virtual u32 flags() const;
        virtual Emulator* createEmulator(DisassemblerAPI *disassembler) const;
        virtual Printer* createPrinter(DisassemblerAPI *disassembler) const;
};

DECLARE_ASSEMBLER_PLUGIN(ARMAssembler, arm)

} // namespace REDasm

#endif // ARM_H
