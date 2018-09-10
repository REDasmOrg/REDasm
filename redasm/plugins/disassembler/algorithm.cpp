#include "algorithm.h"
#include "../../plugins/format.h"

namespace REDasm {

DisassemblerAlgorithm::DisassemblerAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assembler): m_disassembler(disassembler), m_assembler(assembler)
{

}

void DisassemblerAlgorithm::push(address_t address) { this->m_pending.push(address); }
bool DisassemblerAlgorithm::hasNext() const { return !this->m_pending.empty(); }

address_t DisassemblerAlgorithm::next()
{
    address_t address = this->m_pending.top();
    m_pending.pop();
    return address;
}

u32 DisassemblerAlgorithm::disassemble(const Buffer& buffer, InstructionPtr &instruction)
{
    if(this->isDisassembled(instruction->address))
        return DisassemblerAlgorithm::SKIP;

    m_disassembled.insert(instruction->address);

    u32 result = m_assembler->decode(buffer, instruction) ? DisassemblerAlgorithm::OK :
                                                            DisassemblerAlgorithm::FAIL;

    this->onDisassembled(instruction, result);
    return result;
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
            if(segment->is(SegmentTypes::Data) || segment->is(SegmentTypes::Bss))
                m_disassembler->checkLocation(instruction, value); // Create Symbol + XRefs
            else if(segment->is(SegmentTypes::Code))
                m_disassembler->checkString(instruction, value);   // Create Symbol + XRefs

            continue;
        }

        m_disassembler->pushReference(value, instruction);
    }
}

bool DisassemblerAlgorithm::isDisassembled(address_t address) const { return this->m_disassembled.find(address) != this->m_disassembled.end(); }

} // namespace REDasm
