#ifndef METAARM_H
#define METAARM_H

#include "../../plugins/plugins.h"
#include "arm/arm.h"
#include "armthumb/armthumb.h"

namespace REDasm {

class MetaARMAssembler: public AssemblerPlugin
{
    public:
        MetaARMAssembler();
        ~MetaARMAssembler();
        virtual const char* name() const;
        virtual bool decode(Buffer buffer, const InstructionPtr& instruction);

    private:
        void selectAssembler(const InstructionPtr& instruction);

    private:
        ARMAssembler* _armassembler;
        ARMThumbAssembler* _thumbassembler;
        AssemblerPlugin* _currentassembler;
};

DECLARE_ASSEMBLER_PLUGIN(MetaARMAssembler, metaarm)

} // namespace REDasm

#endif // METAARM_H
