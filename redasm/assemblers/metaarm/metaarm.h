#ifndef METAARM_H
#define METAARM_H

#include "../../plugins/plugins.h"
#include "arm.h"
#include "armthumb.h"

namespace REDasm {

class MetaARMAssembler: public AssemblerPlugin
{
    public:
        MetaARMAssembler();
        ~MetaARMAssembler();
        virtual u32 flags() const;
        virtual const char* name() const;
        virtual void prepare(const InstructionPtr& instruction);
        virtual bool decode(Buffer buffer, const InstructionPtr& instruction);
        virtual VMIL::Emulator* createEmulator(DisassemblerAPI *disassembler) const;
        virtual Printer* createPrinter(DisassemblerAPI *disassembler, SymbolTable *symboltable) const;

    private:
        ARMAssembler* _armassembler;
        ARMThumbAssembler* _thumbassembler;
        AssemblerPlugin* _currentassembler;
};

DECLARE_ASSEMBLER_PLUGIN(MetaARMAssembler, metaarm)

} // namespace REDasm

#endif // METAARM_H
