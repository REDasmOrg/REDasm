#include "disassemblerwebchannel.h"

DisassemblerWebChannel::DisassemblerWebChannel(REDasm::DisassemblerAPI *disassembler, QObject *parent) : QObject(parent), m_disassembler(disassembler)
{
    m_document = m_disassembler->document();
    m_cursor = m_document->cursor();
}

void DisassemblerWebChannel::followUnderCursor()
{
    REDasm::SymbolPtr symbol = m_document->symbol(m_cursor->wordUnderCursor());

    if(!symbol || (!symbol->isFunction() && !symbol->is(REDasm::SymbolTypes::Code)))
        return;

    auto it = m_document->instructionItem(symbol->address);

    if(it == m_document->end())
        return;

    this->moveTo(m_document->indexOf(it->get()));
}

void DisassemblerWebChannel::switchToListing() { emit switchView(); }

void DisassemblerWebChannel::moveTo(int line, const QString &word)
{
    if(word.isEmpty())
        m_cursor->clearWordUnderCursor();
    else
        m_cursor->setWordUnderCursor(word.toStdString());

    m_cursor->moveTo(line);

    REDasm::ListingItem* item = m_document->itemAt(line);
    emit addressChanged(item->address);
}
