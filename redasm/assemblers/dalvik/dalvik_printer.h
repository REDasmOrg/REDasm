#ifndef DALVIK_PRINTER_H
#define DALVIK_PRINTER_H

#include "../../plugins/assembler/printer.h"
#include "../../formats/dex/dex_header.h"

namespace REDasm {

class DEXFormat;

class DalvikPrinter : public Printer
{
    public:
        DalvikPrinter(DisassemblerAPI* disassembler, SymbolTable* symboltable);
        virtual void header(const SymbolPtr &symbol, HeaderCallback plgfunc);
        virtual void prologue(const SymbolPtr &symbol, LineCallback prologuefunc);
        virtual void info(const InstructionPtr &instruction, LineCallback infofunc);
        virtual std::string reg(const RegisterOperand &regop) const;
        virtual std::string imm(const Operand& op) const;

    private:
        static std::string registerName(register_t r);
        void startLocal(REDasm::DEXFormat *dexformat, const DEXDebugData& debugdata);
        void restoreLocal(REDasm::DEXFormat *dexformat, register_t r);
        void endLocal(register_t r);

    private:
        DEXDebugInfo _currentdbginfo;
        std::unordered_map<u16, DEXDebugData> _regoverrides;
        std::unordered_map<u16, std::string> _regnames;
};

} // namespace REDasm

#endif // DALVIK_PRINTER_H
