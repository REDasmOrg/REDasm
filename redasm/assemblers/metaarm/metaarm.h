#ifndef METAARM_H
#define METAARM_H

#include "../../plugins/plugins.h"
#include "arm.h"
#include "arm_thumb.h"

namespace REDasm {

class MetaARMAssembler: public AssemblerPlugin
{
    public:
        MetaARMAssembler();
        ~MetaARMAssembler();
        virtual u32 flags() const;
        virtual const char* name() const;
        virtual Emulator* createEmulator(DisassemblerAPI *disassembler) const;
        virtual Printer* createPrinter(DisassemblerAPI *disassembler) const;
        virtual AssemblerAlgorithm* createAlgorithm(DisassemblerAPI *disassembler);
        virtual bool decode(Buffer buffer, const InstructionPtr& instruction);

    public:
        void switchToARM();
        void switchToThumb();

    private:
        ARMAssembler* m_armassembler;
        ARMThumbAssembler* m_thumbassembler;
        AssemblerPlugin* m_assembler;
};

DECLARE_ASSEMBLER_PLUGIN(MetaARMAssembler, metaarm)

} // namespace REDasm

#endif // METAARM_H
