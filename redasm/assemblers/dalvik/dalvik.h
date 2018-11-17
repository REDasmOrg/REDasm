#ifndef DALVIK_H
#define DALVIK_H

// http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html
#include "../../plugins/plugins.h"

#define DEX_DECLARE_DECODE(opcode) bool decode##opcode(BufferRef& buffer, const InstructionPtr& instruction) const

#define DEX_DECLARE_DECODES(op) DEX_DECLARE_DECODE(op##0); DEX_DECLARE_DECODE(op##1); DEX_DECLARE_DECODE(op##2); DEX_DECLARE_DECODE(op##3); \
                                DEX_DECLARE_DECODE(op##4); DEX_DECLARE_DECODE(op##5); DEX_DECLARE_DECODE(op##6); DEX_DECLARE_DECODE(op##7); \
                                DEX_DECLARE_DECODE(op##8); DEX_DECLARE_DECODE(op##9); DEX_DECLARE_DECODE(op##A); DEX_DECLARE_DECODE(op##B); \
                                DEX_DECLARE_DECODE(op##C); DEX_DECLARE_DECODE(op##D); DEX_DECLARE_DECODE(op##E); DEX_DECLARE_DECODE(op##F)

namespace REDasm {

class DalvikAssembler : public AssemblerPlugin
{
    private:
        typedef std::function<bool(BufferRef&, const InstructionPtr&)> DecodeCallback;

    public:
        DalvikAssembler();
        virtual const char* name() const;
        virtual Printer* createPrinter(DisassemblerAPI *disassembler) const;
        virtual AssemblerAlgorithm* createAlgorithm(DisassemblerAPI* disassembler);

    protected:
        virtual bool decodeInstruction(BufferRef& buffer, const InstructionPtr &instruction);

    private:
        bool decodeOp0(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic, u32 type = InstructionTypes::None) const;
        bool decodeOp1(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic, u32 type = InstructionTypes::None) const;
        bool decodeOp2(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic) const;
        bool decodeOp3(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic, u32 type = InstructionTypes::None) const;
        bool decodeOp2_s(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic) const;
        bool decodeOp2_t(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic) const;
        bool decodeOp2_f(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic, u32 type = InstructionTypes::None) const;
        bool decodeOp2_16(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic) const;
        bool decodeOp2_imm4(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic) const;
        bool decodeOp2_imm16(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic) const;
        bool decodeOp2_imm32(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic) const;
        bool decodeOp3_f(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic, u32 type = InstructionTypes::None) const;
        bool decodeOp3_t(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic, u32 type = InstructionTypes::None) const;
        bool decodeOp3_imm8(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic) const;
        bool decodeOp3_imm16(BufferRef& buffer, const InstructionPtr& instruction, const std::string& mnemonic) const;
        bool decodeIfOp2(BufferRef& buffer, const InstructionPtr& instruction, const std::string& cond) const;
        bool decodeIfOp3(BufferRef& buffer, const InstructionPtr& instruction, const std::string& cond) const;
        bool decodeInvoke(BufferRef& buffer, const InstructionPtr& instruction, const std::string& kind) const;

    private:
        DEX_DECLARE_DECODES(0);
        DEX_DECLARE_DECODES(1);
        DEX_DECLARE_DECODES(2);
        DEX_DECLARE_DECODES(3);
        DEX_DECLARE_DECODES(4);
        DEX_DECLARE_DECODES(5);
        DEX_DECLARE_DECODES(6);
        DEX_DECLARE_DECODES(7);
        DEX_DECLARE_DECODES(8);
        DEX_DECLARE_DECODES(9);
        DEX_DECLARE_DECODES(A);
        DEX_DECLARE_DECODES(B);
        DEX_DECLARE_DECODES(C);
        DEX_DECLARE_DECODES(D);
        DEX_DECLARE_DECODES(E);
        DEX_DECLARE_DECODES(F);

    private:
        std::unordered_map<instruction_id_t, DecodeCallback> m_opcodemap;

};

DECLARE_ASSEMBLER_PLUGIN(DalvikAssembler, dalvik)

} // namespace REDasm

#endif // DALVIK_H
