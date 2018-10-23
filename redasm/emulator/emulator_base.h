#ifndef EMULATOR_BASE_H
#define EMULATOR_BASE_H

#include <unordered_map>
#include <unordered_set>
#include <stack>
#include "../plugins/emulator.h"
#include "../redasm.h"

namespace REDasm {

template<typename T> class EmulatorBase: public Emulator
{
    private:
        enum { ErrorFlag = 0xFF };

    private:
        typedef std::unordered_map<T, T> MapT;
        typedef std::unordered_set<T> Flags;
        typedef std::stack<T> Stack;

    public:
        EmulatorBase(DisassemblerAPI* disassembler);
        virtual void emulate(const InstructionPtr& instruction);
        bool readOp(const Operand& op, T* value);
        void writeOp(const Operand& op, T value);

    public:
        void flag(T flag, bool set);
        bool flag(T flag) const;
        void writeReg(T r, T value);
        T readReg(T r) const;
        void writeMem(T address, T value);
        bool readMem(T address, T* value, T size = sizeof(T)) const;

    public:
        virtual bool hasError() const;
        void reset(bool resetmemory = false);
        void unhandled(const InstructionPtr& instruction) const;
        void fail();

    protected:
        bool displacementT(const DisplacementOperand& dispop, T* value);

    private:
        MapT m_registers;
        MapT m_memory;
        Stack m_stack;
        Flags m_flags;
};

} // namespace REDasm

#include "emulator_base.cpp"

#endif // EMULATOR_BASE_H
