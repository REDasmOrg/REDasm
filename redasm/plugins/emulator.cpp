#include "emulator.h"
#include "../disassembler/listing/listingdocument.h"
#include "format.h"
#include <cstring>

namespace REDasm {

Emulator::Emulator(DisassemblerAPI *disassembler): m_disassembler(disassembler) { this->remap(); }

void Emulator::emulate(const InstructionPtr &instruction)
{
    m_currentinstruction = instruction;
    m_dispatcher(instruction->id, instruction);
}

Buffer& Emulator::getSegmentMemory(address_t address, offset_t *offset)
{
    for(auto it = m_memory.begin(); it != m_memory.end(); it++)
    {
        const Segment* segment = it->first;

        if(!segment->contains(address))
            continue;

        *offset = (address - segment->address); // Relative segment offset
        return it->second;
    }

    return Buffer::invalid;
}

BufferRef Emulator::getMemory(address_t address)
{
    offset_t offset = 0;
    Buffer& buffer = this->getSegmentMemory(address, &offset);

    if(buffer.empty())
        return BufferRef();

    return buffer.slice(offset);
}

BufferRef Emulator::getStack(offset_t sp) { return m_stack.slice(sp); }

void Emulator::remap()
{
    ListingDocument* document = m_disassembler->document();
    FormatPlugin* format = m_disassembler->format();

    REDasm::log("MAPPING 'stack'");
    m_stack = format->buffer().createFilled(STACK_SIZE);

    m_memory.clear();

    for(size_t i = 0; i < document->segmentsCount(); i++)
    {
        const Segment* segment = document->segmentAt(i);

        REDasm::log("MAPPING " + REDasm::quoted(segment->name) +
                    " @ " + REDasm::hex(segment->address) + ", " +
                    " size: " + REDasm::hex(segment->size()));

        if(!segment->is(SegmentTypes::Bss))
        {
            BufferRef segmentbuffer = format->buffer(segment->address);

            if(segment->size() > static_cast<s64>(segmentbuffer.size()))
                return;

            Buffer buffer;

            if(!segmentbuffer.copyTo(buffer)) // Mapping failed...
            {
                REDasm::log("Mapping FAILED @ " + REDasm::quoted(segment->name));
                m_memory.clear();
                return;
            }

            m_memory[segment] = std::move(buffer);
        }
        else
        {
            const Buffer& buffer = format->buffer();
            m_memory[segment] = buffer.createFilled(segment->size());
        }
    }
}

} // namespace REDasm
