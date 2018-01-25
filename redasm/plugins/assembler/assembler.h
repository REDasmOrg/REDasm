#ifndef ASSEMBLER_H
#define ASSEMBLER_H

#include <functional>
#include <capstone.h>
#include <stack>
#include <cstring>
#include "../../disassembler/disassemblerapi.h"
#include "../../support/endianness.h"
#include "../../support/utils.h"
#include "../../vmil/vmil_emulator.h"
#include "../base.h"
#include "printer.h"

#define DECLARE_ASSEMBLER_PLUGIN(assembler, id) inline AssemblerPlugin* id##_assemblerPlugin() { return new assembler(); }
#define ASSEMBLER_IS(assembler, arch) (strstr(assembler->name(), arch))

namespace REDasm {

namespace AssemblerFlags {
    enum: u32 { None    = 0, DelaySlot = 1,
                HasVMIL = 0x00010000, EmulateVMIL = 0x00020000 };
}

class AssemblerPlugin: public Plugin
{
    private:
        typedef std::pair<u32, u32> StateItem;

    public:
        AssemblerPlugin();
        virtual u32 flags() const;
        virtual VMIL::Emulator* createEmulator(DisassemblerAPI* disassembler) const;
        virtual Printer* createPrinter(DisassemblerAPI* disassembler, SymbolTable* symboltable) const;
        virtual void analyzeOperand(DisassemblerAPI* disassembler, const InstructionPtr& instruction, const Operand& operand) const;
        virtual bool decode(Buffer buffer, const InstructionPtr& instruction);
        virtual bool done(const InstructionPtr& instruction);

    public:
        template<typename T> T read(Buffer& buffer) const;
        bool hasFlag(u32 flag) const;
        bool hasVMIL() const;
        bool canEmulateVMIL() const;
        endianness_t endianness() const;
        void setEndianness(endianness_t endianness);
        void pushState();
        void popState();

    protected:
        virtual void analyzeRegister(DisassemblerAPI* disassembler, const InstructionPtr& instruction, const Operand &operand) const;
        virtual void analyzeRegisterBranch(address_t target, DisassemblerAPI* disassembler, const InstructionPtr& instruction, const Operand &operand) const;

    private:
        std::stack<StateItem> _statestack;
        endianness_t _endianness;
};

template<typename T> T AssemblerPlugin::read(Buffer& buffer) const
{
    T t = *(reinterpret_cast<T*>(buffer.data));

    if(this->endianness() == Endianness::BigEndian)
        Endianness::cfbe(t);
    else
        Endianness::cfle(t);

    return t;
}

template<cs_arch arch, size_t mode> class CapstoneAssemblerPlugin: public AssemblerPlugin
{
    public:
        CapstoneAssemblerPlugin();
        ~CapstoneAssemblerPlugin();
        virtual bool decode(Buffer buffer, const InstructionPtr& instruction);
        virtual Printer* createPrinter(DisassemblerAPI *disassembler, SymbolTable* symboltable) const { return new CapstonePrinter(this->_cshandle, disassembler, symboltable); }

    protected:
        csh _cshandle;
};

template<cs_arch arch, size_t mode> CapstoneAssemblerPlugin<arch, mode>::CapstoneAssemblerPlugin()
{
    cs_open(arch, static_cast<cs_mode>(mode), &this->_cshandle);
    cs_option(this->_cshandle, CS_OPT_DETAIL, CS_OPT_ON);
}

template<cs_arch arch, size_t mode> CapstoneAssemblerPlugin<arch, mode>::~CapstoneAssemblerPlugin() { cs_close(&this->_cshandle); }

template<cs_arch arch, size_t mode> bool CapstoneAssemblerPlugin<arch, mode>::decode(Buffer buffer, const InstructionPtr& instruction)
{
    u64 address = instruction->address;
    const uint8_t* pdata = reinterpret_cast<const uint8_t*>(buffer.data);
    cs_insn* insn = cs_malloc(this->_cshandle);

    if(!cs_disasm_iter(this->_cshandle, &pdata, reinterpret_cast<size_t*>(&buffer.length), &address, insn))
        return false;

    if(cs_insn_group(this->_cshandle, insn, CS_GRP_JUMP))
        instruction->type |= InstructionTypes::Jump;

    if(cs_insn_group(this->_cshandle, insn, CS_GRP_CALL))
        instruction->type |= InstructionTypes::Call;

    if(cs_insn_group(this->_cshandle, insn, CS_GRP_RET))
        instruction->type |= InstructionTypes::Stop;

    if(cs_insn_group(this->_cshandle, insn, CS_GRP_INT) || cs_insn_group(this->_cshandle, insn, CS_GRP_IRET))
        instruction->type |= InstructionTypes::Privileged;

    instruction->mnemonic = insn->mnemonic;
    instruction->id = insn->id;
    instruction->size = insn->size;
    instruction->userdata = insn;
    instruction->free = [](void* userdata) { cs_free(reinterpret_cast<cs_insn*>(userdata), 1); };

    AssemblerPlugin::decode(buffer, instruction);
    return true;
}

typedef std::function<AssemblerPlugin*()> AssemblerPlugin_Entry;
}

#endif // ASSEMBLER_H
