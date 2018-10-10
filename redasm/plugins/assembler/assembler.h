#ifndef ASSEMBLER_H
#define ASSEMBLER_H

#include <functional>
#include <capstone.h>
#include <stack>
#include <cstring>
#include "../../disassembler/disassemblerapi.h"
#include "../../support/endianness.h"
#include "../../support/utils.h"
#include "../../emulator/emulator.h"
#include "../base.h"
#include "printer.h"

#define DECLARE_ASSEMBLER_PLUGIN(assembler, id) inline AssemblerPlugin* id##_assemblerPlugin() { return new assembler(); }
#define ASSEMBLER_IS(assembler, arch) (strstr(assembler->name(), arch))

namespace REDasm {

namespace AssemblerFlags {
    enum: u32 { None = 0, HasEmulator = 1 };
}

class AssemblerPlugin: public Plugin
{
    private:
        typedef std::pair<u32, u32> StateItem;

    public:
        AssemblerPlugin();
        virtual u32 flags() const;
        virtual Emulator* createEmulator(DisassemblerAPI* disassembler) const;
        virtual Printer* createPrinter(DisassemblerAPI* disassembler) const;
        virtual bool decode(Buffer buffer, const InstructionPtr& instruction);

    public:
        template<typename T> T read(Buffer& buffer) const;
        bool hasFlag(u32 flag) const;
        endianness_t endianness() const;
        void setEndianness(endianness_t endianness);

    private:
        endianness_t m_endianness;
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
        csh handle() const;
        virtual bool decode(Buffer buffer, const InstructionPtr& instruction);
        virtual Printer* createPrinter(DisassemblerAPI *disassembler) const { return new CapstonePrinter(this->m_cshandle, disassembler); }

    protected:
        csh m_cshandle;
};

template<cs_arch arch, size_t mode> CapstoneAssemblerPlugin<arch, mode>::CapstoneAssemblerPlugin()
{
    cs_open(arch, static_cast<cs_mode>(mode), &this->m_cshandle);
    cs_option(this->m_cshandle, CS_OPT_DETAIL, CS_OPT_ON);
}

template<cs_arch arch, size_t mode> CapstoneAssemblerPlugin<arch, mode>::~CapstoneAssemblerPlugin() { cs_close(&this->m_cshandle); }
template<cs_arch arch, size_t mode> csh CapstoneAssemblerPlugin<arch, mode>::handle() const { return this->m_cshandle; }

template<cs_arch arch, size_t mode> bool CapstoneAssemblerPlugin<arch, mode>::decode(Buffer buffer, const InstructionPtr& instruction)
{
    u64 address = instruction->address;
    const uint8_t* pdata = reinterpret_cast<const uint8_t*>(buffer.data);
    cs_insn* insn = cs_malloc(this->m_cshandle);

    if(!cs_disasm_iter(this->m_cshandle, &pdata, reinterpret_cast<size_t*>(&buffer.length), &address, insn))
        return false;

    if(cs_insn_group(this->m_cshandle, insn, CS_GRP_JUMP))
        instruction->type |= InstructionTypes::Jump;

    if(cs_insn_group(this->m_cshandle, insn, CS_GRP_CALL))
        instruction->type |= InstructionTypes::Call;

    if(cs_insn_group(this->m_cshandle, insn, CS_GRP_RET))
        instruction->type |= InstructionTypes::Stop;

    if(cs_insn_group(this->m_cshandle, insn, CS_GRP_INT) || cs_insn_group(this->m_cshandle, insn, CS_GRP_IRET))
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
