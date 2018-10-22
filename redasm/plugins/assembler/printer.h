#ifndef PRINTER_H
#define PRINTER_H

#include <memory>
#include <capstone.h>
#include "../../redasm.h"
#include "../../disassembler/listing/listingdocument.h"
#include "../../disassembler/disassemblerapi.h"

namespace REDasm {

class Printer
{
    public:
        typedef std::function<void(const Operand&, const std::string&, const std::string&)> OpCallback;
        typedef std::function<void(const SymbolPtr&, const std::string&)> SymbolCallback;
        typedef std::function<void(const std::string&, const std::string&, const std::string&)> FunctionCallback;
        typedef std::function<void(const std::string&)> LineCallback;

    public:
        Printer(DisassemblerAPI* disassembler);
        std::string symbol(const SymbolPtr& symbol) const;
        std::string out(const InstructionPtr& instruction) const;

    public:
        virtual void segment(const Segment* segment, LineCallback segmentfunc);
        virtual void function(const SymbolPtr& symbol, FunctionCallback functionfunc);
        virtual void prologue(const SymbolPtr& symbol, LineCallback prologuefunc);
        virtual void symbol(const SymbolPtr& symbol, SymbolCallback symbolfunc) const;
        virtual void info(const InstructionPtr& instruction, LineCallback infofunc);
        virtual std::string out(const InstructionPtr& instruction, OpCallback opfunc) const;

    public: // Operand privitives
        virtual std::string reg(const RegisterOperand& regop) const;
        virtual std::string disp(const DisplacementOperand& dispop) const;
        virtual std::string loc(const Operand& operand) const;
        virtual std::string mem(const Operand& operand) const;
        virtual std::string imm(const Operand& operand) const;
        virtual std::string size(const Operand& operand) const;

    protected:
        DisassemblerAPI* m_disassembler;
        ListingDocument* m_document;
};

class CapstonePrinter: public Printer
{
    public:
        CapstonePrinter(csh cshandle, DisassemblerAPI* disassembler);

    protected:
        virtual std::string reg(const RegisterOperand &regop) const;

    private:
        csh m_cshandle;
};

typedef std::shared_ptr<Printer> PrinterPtr;

}

#endif // PRINTER_H
