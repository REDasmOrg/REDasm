#ifndef EMULATOR_BASE_H
#define EMULATOR_BASE_H

#include <unordered_map>
#include <unordered_set>
#include <type_traits>
#include "../plugins/emulator.h"
#include "../redasm.h"

namespace REDasm {

template<typename T> class EmulatorBase: public Emulator
{
    private:
        enum { ErrorFlag = 0xFF };

    private:
        typedef typename std::make_signed<T>::type ST;
        typedef std::unordered_map<T, T> MapT;
        typedef std::unordered_set<T> Flags;

    public:
        EmulatorBase(DisassemblerAPI* disassembler);
        virtual void emulate(const InstructionPtr& instruction);
        bool readOp(const Operand& op, T* value);

    protected:
        void writeOp(const Operand& op, T value);
        void flag(T flag, bool set);
        bool flag(T flag) const;
        void writeReg(T r, T value);
        T readReg(T r) const;
        void changeReg(const Operand& op, ST amount = 1);
        void changeSP(ST amount);
        bool writeMem(T address, T value, T size = sizeof(T));
        bool readMem(T address, T* value, T size = sizeof(T));

    public:
        virtual bool hasError() const;
        void reset(bool resetmemory = false);
        void unhandled(const InstructionPtr& instruction) const;
        void fail();

    protected:
        bool displacementT(const DisplacementOperand& dispop, T* value);

    private:
        MapT m_registers;
        Flags m_flags;
        T m_sp;
};

} // namespace REDasm

#include "emulator_base.cpp"

#endif // EMULATOR_BASE_H
