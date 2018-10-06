#include "disassemblerwebchannel.h"

DisassemblerWebChannel::DisassemblerWebChannel(REDasm::DisassemblerAPI *disassembler, QObject *parent) : QObject(parent), m_disassembler(disassembler)
{
    m_document = m_disassembler->document();
    m_cursor = m_document->cursor();
}

void DisassemblerWebChannel::switchToListing() { emit switchView(); }

void DisassemblerWebChannel::moveTo(int line, const QString &word)
{
    m_cursor->setWordUnderCursor(word.toStdString());
    m_cursor->moveTo(line);

    REDasm::ListingItem* item = m_document->itemAt(line);
    emit addressChanged(item->address);
}
