#ifndef ASSEMBLER_H
#define ASSEMBLER_H

#include <functional>
#include <capstone.h>
#include <stack>
#include <cstring>
#include "../../disassembler/disassemblerapi.h"
#include "../../support/dispatcher.h"
#include "../../support/utils.h"
#include "../../plugins/emulator.h"
#include "../base.h"
#include "printer.h"

#define DECLARE_ASSEMBLER_PLUGIN(assembler, id) inline AssemblerPlugin* id##_assemblerPlugin() { return new assembler(); }
#define ASSEMBLER_IS(assembler, arch)           (strstr(assembler->name(), arch))
#define REGISTER_INSTRUCTION(id, cb)            this->m_dispatcher[id] = std::bind(cb, this, std::placeholders::_1)
#define SET_INSTRUCTION_TYPE(id, type)          this->m_instructiontypes[id] = type

namespace REDasm {

namespace AssemblerFlags {
    enum: u32 { None = 0, HasEmulator = 1 };
}

class AssemblerAlgorithm;

class AssemblerPlugin: public Plugin
{
    public:
        AssemblerPlugin();
        virtual u32 flags() const;
        virtual Emulator* createEmulator(DisassemblerAPI* disassembler) const;
        virtual Printer* createPrinter(DisassemblerAPI* disassembler) const;
        virtual AssemblerAlgorithm* createAlgorithm(DisassemblerAPI* disassembler);
        bool hasFlag(u32 flag) const;
        endianness_t endianness() const;
        void setEndianness(endianness_t endianness);
        virtual bool decode(BufferRef& buffer, const InstructionPtr& instruction);
        virtual bool decodeInstruction(BufferRef& buffer, const InstructionPtr& instruction);

    protected:
        virtual void onDecoded(const InstructionPtr& instruction);

    private:
        void setInstructionType(const InstructionPtr& instruction) const;

    protected:
        std::unordered_map<instruction_id_t, u32> m_instructiontypes;
        Dispatcher<instruction_id_t, void(const InstructionPtr&)> m_dispatcher;

    private:
        endianness_t m_endianness;
};

template<cs_arch arch, size_t mode> class CapstoneAssemblerPlugin: public AssemblerPlugin
{
    public:
        CapstoneAssemblerPlugin();
        ~CapstoneAssemblerPlugin();
        csh handle() const;
        virtual Printer* createPrinter(DisassemblerAPI *disassembler) const { return new CapstonePrinter(this->m_cshandle, disassembler); }
        virtual bool decodeInstruction(BufferRef& buffer, const InstructionPtr& instruction);

    protected:
        virtual void onDecoded(const InstructionPtr& instruction);

    protected:
        csh m_cshandle;
};

template<cs_arch arch, size_t mode> CapstoneAssemblerPlugin<arch, mode>::CapstoneAssemblerPlugin(): AssemblerPlugin()
{
    cs_open(arch, static_cast<cs_mode>(mode), &this->m_cshandle);
    cs_option(this->m_cshandle, CS_OPT_DETAIL, CS_OPT_ON);
}

template<cs_arch arch, size_t mode> void CapstoneAssemblerPlugin<arch, mode>::onDecoded(const InstructionPtr& instruction)
{
    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userdata);

    if(!insn)
        return;

    if(cs_insn_group(m_cshandle, insn, CS_GRP_JUMP))
        instruction->type |= InstructionTypes::Jump;
    else if(cs_insn_group(m_cshandle, insn, CS_GRP_CALL))
        instruction->type |= InstructionTypes::Call;
    else if(cs_insn_group(m_cshandle, insn, CS_GRP_RET))
        instruction->type |= InstructionTypes::Stop;
    else if(cs_insn_group(m_cshandle, insn, CS_GRP_INT) || cs_insn_group(m_cshandle, insn, CS_GRP_IRET))
        instruction->type |= InstructionTypes::Privileged;
}

template<cs_arch arch, size_t mode> CapstoneAssemblerPlugin<arch, mode>::~CapstoneAssemblerPlugin() { cs_close(&this->m_cshandle); }
template<cs_arch arch, size_t mode> csh CapstoneAssemblerPlugin<arch, mode>::handle() const { return this->m_cshandle; }

template<cs_arch arch, size_t mode> bool CapstoneAssemblerPlugin<arch, mode>::decodeInstruction(BufferRef& buffer, const InstructionPtr& instruction)
{
    u64 address = instruction->address;
    const uint8_t* pdata = static_cast<const uint8_t*>(buffer);
    size_t len = buffer.size();
    cs_insn* insn = cs_malloc(m_cshandle);

    if(!cs_disasm_iter(m_cshandle, &pdata, &len, &address, insn))
        return false;

    instruction->mnemonic = insn->mnemonic;
    instruction->id = insn->id;
    instruction->size = insn->size;
    instruction->userdata = insn;
    instruction->free = [](void* userdata) { cs_free(reinterpret_cast<cs_insn*>(userdata), 1); };
    return true;
}

typedef std::function<AssemblerPlugin*()> AssemblerPlugin_Entry;
}

#endif // ASSEMBLER_H
