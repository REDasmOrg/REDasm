#ifndef MIPS_H
#define MIPS_H

#include "../../plugins/plugins.h"
#include "mips_printer.h"
#include "mips_emulator.h"
#include "mips_quirks.h"

namespace REDasm {

template<size_t mode> class MIPSAssembler: public CapstoneAssemblerPlugin<CS_ARCH_MIPS, mode>
{
    public:
        MIPSAssembler();
        virtual const char* name() const;
        virtual u32 flags() const { return AssemblerFlags::HasEmulator; }
        virtual Emulator* createEmulator(DisassemblerAPI *disassembler) const { return new MIPSEmulator(disassembler); }
        virtual Printer* createPrinter(DisassemblerAPI* disassembler) const { return new MIPSPrinter(this->m_cshandle, disassembler); }

    protected:
        virtual bool decodeInstruction(BufferRef& buffer, const InstructionPtr& instruction);
        virtual void onDecoded(const InstructionPtr& instruction);

    private:
        void setTargetOp0(const InstructionPtr& instruction) const { instruction->targetOp(0); }
        void setTargetOp1(const InstructionPtr& instruction) const { instruction->targetOp(1); }
        void setTargetOp2(const InstructionPtr& instruction) const { instruction->targetOp(2); }
        void checkJr(const InstructionPtr& instruction) const;
};

typedef MIPSAssembler<CS_MODE_MIPS32> MIPS32Assembler;
typedef MIPSAssembler<CS_MODE_MIPS64> MIPS64Assembler;

DECLARE_ASSEMBLER_PLUGIN(MIPS32Assembler, mips32)
DECLARE_ASSEMBLER_PLUGIN(MIPS64Assembler, mips64)

} // namespace REDasm

#include "mips.cpp"

#endif // MIPS_H
