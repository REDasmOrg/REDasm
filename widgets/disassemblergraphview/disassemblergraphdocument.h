#ifndef DISASSEMBLERGRAPHDOCUMENT_H
#define DISASSEMBLERGRAPHDOCUMENT_H

#include "../disassemblerview/disassemblerdocument.h"

class DisassemblerGraphDocument : public DisassemblerDocument
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphDocument(REDasm::Disassembler* disassembler, QTextDocument *document, QObject* parent = 0);
        virtual void generate(const REDasm::InstructionPtr& instruction, const QTextCursor &cursor);
        virtual void generate(const REDasm::SymbolPtr& symbol, const QTextCursor cursor);

    protected:
        virtual int indentWidth() const;
        virtual void insertAddress(address_t address);
        virtual void appendPathInfo(const REDasm::InstructionPtr &instruction);
};

#endif // DISASSEMBLERGRAPHDOCUMENT_H
