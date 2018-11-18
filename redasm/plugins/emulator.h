#ifndef EMULATOR_H
#define EMULATOR_H

#include "../disassembler/disassemblerapi.h"
#include "../support/dispatcher.h"

#define EMULATE_INSTRUCTION(id, callback) m_dispatcher[id] = std::bind(callback, this, std::placeholders::_1)
#define STACK_SIZE                        0xFFFF

namespace REDasm {

class Emulator
{
    private:
        typedef Dispatcher<instruction_id_t, void(const InstructionPtr&)> DispatcherType;
        typedef std::unordered_map<const Segment*, Buffer> MappedMemory;

    public:
        Emulator(DisassemblerAPI* disassembler);
        virtual void emulate(const InstructionPtr& instruction);
        virtual bool hasError() const = 0;
        virtual bool read(const Operand& op, u64* value) = 0;
        virtual bool displacement(const Operand& op, u64* value) = 0;

    protected:
        Buffer& getSegmentMemory(address_t address, offset_t* offset);
        BufferRef getMemory(address_t address);
        BufferRef getStack(offset_t sp);

    private:
        void remap();

    protected:
        InstructionPtr m_currentinstruction;
        DisassemblerAPI* m_disassembler;
        DispatcherType m_dispatcher;
        MappedMemory m_memory;
        Buffer m_stack;
};

} // namespace REDasm

#endif // EMULATOR_H
