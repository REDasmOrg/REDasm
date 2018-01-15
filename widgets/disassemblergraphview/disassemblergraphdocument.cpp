#include "disassemblergraphdocument.h"

DisassemblerGraphDocument::DisassemblerGraphDocument(REDasm::Disassembler *disassembler, const QString &theme, QTextDocument *document, QObject *parent): DisassemblerDocument(disassembler, theme, document, parent)
{
}

void DisassemblerGraphDocument::generate(const REDasm::InstructionPtr &instruction, const QTextCursor& cursor)
{
    this->_textcursor = cursor;
    this->appendInstruction(instruction);
}

void DisassemblerGraphDocument::generate(const REDasm::SymbolPtr &symbol, const QTextCursor cursor)
{
    this->_textcursor = cursor;
    this->appendLabel(symbol);
}

int DisassemblerGraphDocument::indentWidth() const
{
    return 0;
}

void DisassemblerGraphDocument::appendAddress(address_t address)
{
    RE_UNUSED(address);
}

void DisassemblerGraphDocument::appendPathInfo(const REDasm::InstructionPtr &instruction)
{
    RE_UNUSED(instruction);
}
