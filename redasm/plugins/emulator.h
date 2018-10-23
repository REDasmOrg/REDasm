#ifndef EMULATOR_H
#define EMULATOR_H

#include "../disassembler/disassemblerapi.h"
#include "../support/dispatcher.h"

#define EMULATE_INSTRUCTION(id, callback) m_dispatcher[id] = std::bind(callback, this, std::placeholders::_1)

namespace REDasm {

class Emulator
{
    private:
        typedef Dispatcher<instruction_id_t, void(const InstructionPtr&)> DispatcherType;

    public:
        Emulator(DisassemblerAPI* disassembler);
        virtual void emulate(const InstructionPtr& instruction);
        virtual bool hasError() const = 0;
        virtual bool read(const Operand& op, u64* value) = 0;
        virtual bool displacement(const Operand& op, u64* value) = 0;

    protected:
        InstructionPtr m_currentinstruction;
        DisassemblerAPI* m_disassembler;
        DispatcherType m_dispatcher;
};

} // namespace REDasm

#endif // EMULATOR_H
