#include "format.h"
#include "../disassembler/algorithm/controlflow.h"

namespace REDasm {

FormatPlugin::FormatPlugin(const Buffer &buffer): Plugin(), m_buffer(buffer) { m_document.m_format = this; }
ListingDocument *FormatPlugin::document() { return &m_document; }
const SignatureFiles &FormatPlugin::signatures() const { return m_signatures; }
u64 FormatPlugin::addressWidth() const { return this->bits() / 8; }

offset_t FormatPlugin::offset(address_t address) const
{
    for(size_t i = 0; i < m_document.segmentsCount(); i++)
    {
        const Segment* segment = m_document.segmentAt(i);

        if(segment->contains(address))
            return (address - segment->address) + segment->offset;
    }

    return address;
}

Analyzer* FormatPlugin::createAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles& signatures) const { return new Analyzer(disassembler, signatures); }
DisassemblerAlgorithm *FormatPlugin::createAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assemblerplugin) const { return new DisassemblerControlFlow(disassembler, assemblerplugin); }
u32 FormatPlugin::flags() const { return FormatFlags::None; }
endianness_t FormatPlugin::endianness() const { return Endianness::LittleEndian; /* Use LE by default */ }
bool FormatPlugin::isBinary() const { return this->flags() & FormatFlags::Binary; }
const Buffer &FormatPlugin::buffer() const { return m_buffer; }

}
