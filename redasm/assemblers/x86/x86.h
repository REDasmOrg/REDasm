#ifndef X86_H
#define X86_H

#include "../../plugins/plugins.h"
#include "x86_printer.h"

#define X86_REGISTER(reg) ((reg == X86_REG_INVALID) ? REGISTER_INVALID : reg)

namespace REDasm {

template<cs_mode mode> class X86Assembler: public CapstoneAssemblerPlugin<CS_ARCH_X86, mode>
{
    public:
        X86Assembler();
        virtual const char* name() const;
        virtual Printer* createPrinter(DisassemblerAPI *disassembler) const { return new X86Printer(this->m_cshandle, disassembler); }

    protected:
        virtual void onDecoded(const InstructionPtr& instruction);

    private:
        void resetStackSize(const InstructionPtr&) { m_stacksize = 0; }
        void initStackSize(const InstructionPtr& instruction);
        void setBranchTarget(const InstructionPtr& instruction);
        void checkLea(const InstructionPtr& instruction);
        s64 localIndex(s64 disp, u32& type) const;
        s64 stackLocalIndex(s64 disp) const;
        bool isSP(register_t reg) const;
        bool isBP(register_t reg) const;
        bool isIP(register_t reg) const;

    private:
        s64 m_stacksize;
};


typedef X86Assembler<CS_MODE_16> X86_16Assembler;
typedef X86Assembler<CS_MODE_32> X86_32Assembler;
typedef X86Assembler<CS_MODE_64> X86_64Assembler;

DECLARE_ASSEMBLER_PLUGIN(X86_16Assembler, x86_16)
DECLARE_ASSEMBLER_PLUGIN(X86_32Assembler, x86_32)
DECLARE_ASSEMBLER_PLUGIN(X86_64Assembler, x86_64)

} // namespace REDasm

#include "x86.cpp"

#endif // X86_H
