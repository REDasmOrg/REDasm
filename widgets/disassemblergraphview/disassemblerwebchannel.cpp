#include "disassemblerwebchannel.h"
#include "../../redasm/disassembler/listing/listingdocument.h"

DisassemblerWebChannel::DisassemblerWebChannel(REDasm::DisassemblerAPI *disassembler, QObject *parent) : QObject(parent), m_disassembler(disassembler) { }

void DisassemblerWebChannel::updateLine(int line)
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    doc->cursor()->moveTo(line);
}
