#ifndef CIL_H
#define CIL_H

#include "../../plugins/plugins.h"

namespace REDasm {

class CILAssembler : public AssemblerPlugin
{
    public:
        CILAssembler();
        virtual const char* name() const;

    protected:
        virtual bool decodeInstruction(BufferRef& buffer, const InstructionPtr& instruction);
};

DECLARE_ASSEMBLER_PLUGIN(CILAssembler, cil)

} // namespace REDasm

#endif // CIL_H
