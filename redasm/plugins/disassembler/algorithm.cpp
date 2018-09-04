#include "algorithm.h"
#include "../../plugins/format.h"

namespace REDasm {

DisassemblerAlgorithm::DisassemblerAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assembler): _disassembler(disassembler), _assembler(assembler)
{

}

void DisassemblerAlgorithm::push(address_t address) { this->_pending.push(address); }
bool DisassemblerAlgorithm::hasNext() const { return !this->_pending.empty(); }

address_t DisassemblerAlgorithm::next()
{
    address_t address = this->_pending.top();
    this->_pending.pop();
    return address;
}

u32 DisassemblerAlgorithm::disassemble(const Buffer& buffer, InstructionPtr &instruction)
{
    if(this->isDisassembled(instruction->address))
        return DisassemblerAlgorithm::SKIP;

    this->_disassembled.insert(instruction->address);

    u32 result = this->_assembler->decode(buffer, instruction) ? DisassemblerAlgorithm::OK :
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
    FormatPlugin* formatplugin = this->_disassembler->format();
    SymbolTable* symboltable = this->_disassembler->symbolTable();

    for(const Operand& op : instruction->operands)
    {
        if(!op.isNumeric())
            continue;

        u64 value = op.u_value;
        const Segment* segment = formatplugin->segment(value);

        if(!segment)
            continue;

        if(op.isRead() && this->_disassembler->dereferenceOperand(op, &value))
        {
            segment = formatplugin->segment(value);
            symboltable->createLocation(op.u_value, SymbolTypes::Data | SymbolTypes::Pointer); // Create Symbol for pointer
            this->_disassembler->pushReference(op.u_value, instruction);
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
                symboltable->createLocation(value, SymbolTypes::Code);
            }
            else
            {
                this->_disassembler->checkJumpTable(instruction, op.u_value);
                continue;
            }
        }
        else if(instruction->is(InstructionTypes::Call) && instruction->isTargetOperand(op))
        {
            if(segment != formatplugin->entryPointSegment())
                symboltable->createFunction(value, segment);
            else
                symboltable->createFunction(value);
        }
        else
        {
            if(segment->is(SegmentTypes::Data) || segment->is(SegmentTypes::Bss))
                this->_disassembler->checkLocation(instruction, value); // Create Symbol + XRefs
            else if(segment->is(SegmentTypes::Code))
                this->_disassembler->checkString(instruction, value);   // Create Symbol + XRefs

            continue;
        }

        this->_disassembler->pushReference(value, instruction);
    }
}

bool DisassemblerAlgorithm::isDisassembled(address_t address) const { return this->_disassembled.find(address) != this->_disassembled.end(); }

} // namespace REDasm
