#ifndef CHIP8_H
#define CHIP8_H

/*
 * References:
 * - http://www.multigesture.net/wp-content/uploads/mirror/goldroad/chip8_instruction_set.shtml
 * - https://en.wikipedia.org/wiki/CHIP-8
 * - https://massung.github.io/CHIP-8
 */

#include "../../plugins/plugins.h"
#include "chip8_registers.h"

namespace REDasm {

class CHIP8Assembler : public AssemblerPlugin
{
    private:
        typedef std::function<bool(u16, const InstructionPtr& instruction)> OpCodeCallback;

    public:
        CHIP8Assembler();
        virtual const char* name() const;
        virtual Printer* createPrinter(DisassemblerAPI *disassembler) const;

    protected:
        virtual bool decodeInstruction(BufferRef& buffer, const InstructionPtr& instruction);
        virtual void onDecoded(const InstructionPtr& instruction) const;

    private:
        bool decode0xxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decode1xxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decode2xxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decode3xxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decode4xxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decode5xxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decode6xxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decode7xxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decode8xxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decode9xxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decodeAxxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decodeBxxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decodeCxxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decodeDxxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decodeExxx(u16 opcode, const InstructionPtr& instruction) const;
        bool decodeFxxx(u16 opcode, const InstructionPtr& instruction) const;

    private:
        std::map<u16, OpCodeCallback> m_opcodemap;
};

DECLARE_ASSEMBLER_PLUGIN(CHIP8Assembler, chip8)

} // namespace REDasm

#endif // CHIP8_H
