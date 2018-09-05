#include "disassemblergraphdocument.h"

DisassemblerGraphDocument::DisassemblerGraphDocument(REDasm::Disassembler *disassembler, QTextDocument *document, QObject *parent): DisassemblerDocument(disassembler, document, parent)
{
}

void DisassemblerGraphDocument::generate(const REDasm::InstructionPtr &instruction, const QTextCursor& cursor)
{
    this->_textcursor = cursor;
    //this->insertInstruction(instruction);
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

void DisassemblerGraphDocument::insertAddress(address_t address)
{
    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("address_fg"));

    this->_textcursor.setCharFormat(charformat);
    this->_textcursor.insertText(HEX_ADDRESS(address) + " ");
}

void DisassemblerGraphDocument::appendPathInfo(const REDasm::InstructionPtr &instruction)
{
    RE_UNUSED(instruction);
}
