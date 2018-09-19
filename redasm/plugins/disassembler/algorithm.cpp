#include "algorithm.h"
#include "../../plugins/format.h"
#include <thread>

#define INVALID_MNEMONIC "db"

namespace REDasm {

DisassemblerAlgorithm::DisassemblerAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assembler): m_disassembler(disassembler), m_assembler(assembler), m_currentsegment(NULL), m_analyzed(false)
{
    m_format = m_disassembler->format();
    m_document = m_disassembler->document();
}

void DisassemblerAlgorithm::push(address_t address) { m_pending.push(address); }

bool DisassemblerAlgorithm::analyze()
{
    if(m_analyzed)
        return false;

    m_analyzed = true;

    FormatPlugin* format = m_disassembler->format();
    m_analyzer.reset(format->createAnalyzer(m_disassembler, format->signatures()));

    std::thread([&]() {
        REDasm::status("Analyzing...");
        m_analyzer->analyze();
        m_document->moveToEP();
    }).detach();

    return true;
}

bool DisassemblerAlgorithm::hasNext() const { return !m_pending.empty(); }

address_t DisassemblerAlgorithm::next()
{
    address_t address = m_pending.top();
    m_pending.pop();
    return address;
}

u32 DisassemblerAlgorithm::disassemble(address_t address, const InstructionPtr &instruction)
{
    auto it = m_disassembled.find(address);

    if(it != m_disassembled.end())
        return DisassemblerAlgorithm::SKIP;

    m_disassembled.insert(address);

    if(!this->canBeDisassembled(address))
        return DisassemblerAlgorithm::SKIP;

    Buffer buffer = m_format->buffer() + m_format->offset(address);
    instruction->address = address;
    u32 result = m_assembler->decode(buffer, instruction) ? DisassemblerAlgorithm::OK :
                                                            DisassemblerAlgorithm::FAIL;

    if(result == DisassemblerAlgorithm::FAIL)
        this->createInvalidInstruction(instruction, buffer);

    this->onDisassembled(instruction, result);
    return result;
}

u32 DisassemblerAlgorithm::disassembleSingle(address_t address, const InstructionPtr& instruction)
{
    if(!this->canBeDisassembled(address))
        return DisassemblerAlgorithm::SKIP;

    Buffer buffer = m_format->buffer() + m_format->offset(address);

    if(buffer.eob())
        return DisassemblerAlgorithm::SKIP;

    instruction->address = address;
    return m_assembler->decode(buffer, instruction) ? DisassemblerAlgorithm::OK :
                                                      DisassemblerAlgorithm::FAIL;
}

void DisassemblerAlgorithm::onDisassembled(const InstructionPtr &instruction, u32 result)
{
    if(result == DisassemblerAlgorithm::FAIL)
        return;

    this->checkOperands(instruction);
}

void DisassemblerAlgorithm::checkOperands(const InstructionPtr &instruction)
{
    ListingDocument* document = m_disassembler->document();

    for(const Operand& op : instruction->operands)
    {
        if(!op.isNumeric())
            continue;

        u64 value = op.u_value;
        const Segment* segment = document->segment(value);

        if(!segment)
            continue;

        if(op.isRead() && m_disassembler->dereferenceOperand(op, &value))
        {
            segment = document->segment(value);

            if(!segment)
                continue;

            document->symbol(op.u_value, SymbolTypes::Data | SymbolTypes::Pointer); // Create Symbol for pointer
            m_disassembler->pushReference(op.u_value, instruction);
        }

        if(instruction->is(InstructionTypes::Jump) && instruction->isTargetOperand(op))
        {
            if(!op.is(OperandTypes::Memory))
            {
                int dir = BRANCH_DIRECTION(instruction, value);

                if(dir < 0)
                    instruction->cmt("Possible loop");
                else if(!dir)
                    instruction->cmt("Infinite loop");

                instruction->target(value);
                document->symbol(value, SymbolTypes::Code);
            }
            else
            {
                m_disassembler->checkJumpTable(instruction, op.u_value);
                continue;
            }
        }
        else if(instruction->is(InstructionTypes::Call) && instruction->isTargetOperand(op))
            document->symbol(value, SymbolTypes::Function);
        else
        {
            if(segment->is(SegmentTypes::Code))
                m_disassembler->checkString(instruction, value);   // Create Symbol + XRefs
            else if(segment->is(SegmentTypes::Data) || segment->is(SegmentTypes::Bss))
                m_disassembler->checkLocation(instruction, value); // Create Symbol + XRefs

            continue;
        }

        m_disassembler->pushReference(value, instruction);
    }
}

bool DisassemblerAlgorithm::canBeDisassembled(address_t address)
{
    Buffer buffer = m_format->buffer() + m_format->offset(address);

    if(buffer.eob())
        return false;

    if(!m_currentsegment || !m_currentsegment->contains(address))
        m_currentsegment = m_document->segment(address);

    if(!m_currentsegment || !m_currentsegment->is(SegmentTypes::Code))
        return false;

    SymbolPtr symbol = m_document->symbol(address);

    if(symbol && !symbol->is(SymbolTypes::Code))
        return false;

    return true;
}

void DisassemblerAlgorithm::createInvalidInstruction(const InstructionPtr &instruction, const Buffer& buffer)
{
    if(!instruction->size)
        instruction->size = 1; // Invalid instruction uses at least 1 byte

    instruction->type = InstructionTypes::Invalid;
    instruction->mnemonic = INVALID_MNEMONIC;

    if(!instruction->bytes.empty())
        return;

    std::stringstream ss;
    ss << std::hex << static_cast<size_t>(*buffer);
    instruction->bytes = ss.str();
}

} // namespace REDasm
