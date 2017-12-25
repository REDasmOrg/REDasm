#ifndef CHIP8PROCESSOR_H
#define CHIP8PROCESSOR_H

/*
 * References:
 * - http://www.multigesture.net/wp-content/uploads/mirror/goldroad/chip8_instruction_set.shtml
 * - https://en.wikipedia.org/wiki/CHIP-8
 * - https://massung.github.io/CHIP-8
 */

#include "../../plugins/plugins.h"

#define CHIP8_REG_V0_ID 0x0
#define CHIP8_REG_V1_ID 0x1
#define CHIP8_REG_V2_ID 0x2
#define CHIP8_REG_V3_ID 0x3
#define CHIP8_REG_V4_ID 0x4
#define CHIP8_REG_V5_ID 0x5
#define CHIP8_REG_V6_ID 0x6
#define CHIP8_REG_V7_ID 0x7
#define CHIP8_REG_V8_ID 0x8
#define CHIP8_REG_V9_ID 0x9
#define CHIP8_REG_VA_ID 0xA
#define CHIP8_REG_VB_ID 0xB
#define CHIP8_REG_VC_ID 0xC
#define CHIP8_REG_VD_ID 0xD
#define CHIP8_REG_VE_ID 0xE
#define CHIP8_REG_VF_ID 0xF

#define CHIP8_REG_I_ID  static_cast<register_t>('i')
#define CHIP8_REG_DT_ID static_cast<register_t>('d')
#define CHIP8_REG_ST_ID static_cast<register_t>('s')

namespace REDasm {

class CHIP8Processor : public ProcessorPlugin
{
    private:
        typedef std::function<bool(u16, const InstructionPtr& instruction)> OpCodeCallback;

    public:
        CHIP8Processor();
        virtual const char* name() const;
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
