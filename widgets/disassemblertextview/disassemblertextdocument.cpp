#include "disassemblertextdocument.h"

DisassemblerTextDocument::DisassemblerTextDocument(REDasm::Disassembler *disassembler, const QString &theme, QTextDocument *document, QObject *parent): DisassemblerDocument(disassembler, theme, document, parent)
{
}

bool DisassemblerTextDocument::generate(address_t address, const QTextCursor &cursor)
{
    if(!DisassemblerDocument::generate(address, cursor))
        return false;

    this->moveToBlock(address);
    this->_textcursor.beginEditBlock();

    REDasm::Listing& listing = this->_disassembler->listing();

    listing.iterateFunction(address, [this](const REDasm::InstructionPtr& i) { this->appendInstruction(i); },
                                     [this](const REDasm::SymbolPtr& s) { this->appendFunctionStart(s); },
                                     [this](const REDasm::InstructionPtr& i) { this->appendFunctionEnd(i); },
                                     [this](const REDasm::SymbolPtr& s) { this->appendLabel(s); });

    this->_textcursor.endEditBlock();
    return true;
}

void DisassemblerTextDocument::moveToBlock(address_t address)
{
    QTextBlock b = this->_textcursor.block();

    if(!b.blockFormat().hasProperty(DisassemblerDocument::Address))
        b = this->_document->begin();

    address_t currentaddress = b.blockFormat().property(DisassemblerDocument::Address).toULongLong();
    bool searchforward = address > currentaddress;

    for(; b.isValid(); b = searchforward ? b.next() : b.previous())
    {
        QTextBlockFormat blockformat = b.blockFormat();
        address_t blockaddress = blockformat.property(DisassemblerDocument::Address).toULongLong();

        if(!searchforward && (blockaddress < address))
        {
            if(b.isValid())
                b = b.next(); // Insert data from the next block

            break;
        }

        if(searchforward && (blockaddress > address))
        {
            if(b.isValid())
                b = b.previous();  // Insert data from the previous block

            break;
        }
    }

    if(!b.isValid())
        this->_textcursor.movePosition(searchforward ? QTextCursor::End : QTextCursor::Start);
    else
        this->_textcursor.setPosition(b.position());
}
