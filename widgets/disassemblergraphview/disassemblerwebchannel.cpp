#include "disassemblerwebchannel.h"

DisassemblerWebChannel::DisassemblerWebChannel(REDasm::DisassemblerAPI *disassembler, QObject *parent) : QObject(parent), m_document(disassembler->document()), m_disassembler(disassembler)
{
    m_cursor = m_document->cursor();
}

void DisassemblerWebChannel::followUnderCursor()
{
    const REDasm::Symbol* symbol = m_document->symbol(m_cursor->wordUnderCursor());

    if(!symbol || (!symbol->isFunction() && !symbol->is(REDasm::SymbolTypes::Code)))
        return;

    auto it = m_document->instructionItem(symbol->address);

    if(it == m_document->end())
        return;

    this->moveTo(m_document->indexOf(it->get()));
}

void DisassemblerWebChannel::showReferencesUnderCursor()
{
    const REDasm::Symbol* symbol = m_document->symbol(m_cursor->wordUnderCursor());

    if(!symbol)
        return;

    emit referencesRequested(symbol->address);
}

void DisassemblerWebChannel::switchToListing() { emit switchView(); }

void DisassemblerWebChannel::moveTo(int line, const QString &word)
{
    if(word.isEmpty())
        m_cursor->clearWordUnderCursor();
    else
        m_cursor->setWordUnderCursor(word.toStdString());

    if(line == m_cursor->currentLine()) // Don't flood web channel
        return;

    m_cursor->moveTo(line);
}
