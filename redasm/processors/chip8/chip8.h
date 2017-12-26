#ifndef CHIP8PROCESSOR_H
#define CHIP8PROCESSOR_H

/*
 * References:
 * - http://www.multigesture.net/wp-content/uploads/mirror/goldroad/chip8_instruction_set.shtml
 * - https://en.wikipedia.org/wiki/CHIP-8
 * - https://massung.github.io/CHIP-8
 */

#include "../../plugins/plugins.h"
#include "chip8registers.h"

namespace REDasm {

class CHIP8Processor : public ProcessorPlugin
{
    private:
        typedef std::function<bool(u16, const InstructionPtr& instruction)> OpCodeCallback;

    public:
        CHIP8Processor();
        virtual const char* name() const;
        virtual u32 flags() const;
        virtual VMIL::Emulator* createEmulator(DisassemblerFunctions* disassembler) const;
        virtual Printer* createPrinter(DisassemblerFunctions *disassembler, SymbolTable* symboltable) const;
        virtual bool decode(Buffer buffer, const InstructionPtr& instruction);

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
        std::map<u16, OpCodeCallback> _opcodemap;
};

DECLARE_PROCESSOR_PLUGIN(chip8, CHIP8Processor)

} // namespace REDasm

#endif // CHIP8PROCESSOR_H
