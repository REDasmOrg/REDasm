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
        virtual bool decode(Buffer buffer, const InstructionPtr& instruction);
        virtual Emulator* createEmulator(DisassemblerAPI *disassembler) const;
        virtual Printer* createPrinter(DisassemblerAPI *disassembler) const;

    private:
        ARMAssembler* m_armassembler;
        ARMThumbAssembler* m_thumbassembler;
};

DECLARE_ASSEMBLER_PLUGIN(MetaARMAssembler, metaarm)

} // namespace REDasm

#endif // METAARM_H
