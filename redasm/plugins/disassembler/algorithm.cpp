#include "algorithm.h"
#include "../../plugins/format.h"
#include <thread>

#define INVALID_MNEMONIC "db"
#define ENQUEUE_DECODE_STATE(address) ENQUEUE_STATE(DisassemblerAlgorithm::DecodeState, address, -1, NULL)

namespace REDasm {

DisassemblerAlgorithm::DisassemblerAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assembler): StateMachine(), m_disassembler(disassembler), m_assembler(assembler), m_currentsegment(NULL), m_analyzed(false)
{
    m_format = m_disassembler->format();
    m_document = m_disassembler->document();

    REGISTER_STATE(DisassemblerAlgorithm::DecodeState, &DisassemblerAlgorithm::decodeState);
    REGISTER_STATE(DisassemblerAlgorithm::JumpState, &DisassemblerAlgorithm::jumpState);
    REGISTER_STATE(DisassemblerAlgorithm::CallState, &DisassemblerAlgorithm::callState);
    REGISTER_STATE(DisassemblerAlgorithm::AddressTableState, &DisassemblerAlgorithm::addressTableState);
    REGISTER_STATE(DisassemblerAlgorithm::MemoryState, &DisassemblerAlgorithm::memoryState);
    REGISTER_STATE(DisassemblerAlgorithm::ImmediateState, &DisassemblerAlgorithm::immediateState);
}

void DisassemblerAlgorithm::enqueue(address_t address) { ENQUEUE_DECODE_STATE(address); }

bool DisassemblerAlgorithm::analyze()
{
    if(m_analyzed)
        return false;

    m_analyzed = true;

    FormatPlugin* format = m_disassembler->format();
    m_analyzer.reset(format->createAnalyzer(m_disassembler, format->signatures()));

    if(getenv("SYNC_MODE"))
    {
        m_analyzer->analyze();
        m_document->moveToEP();
    }
    else
    {
        std::thread([&]() {
            REDasm::status("Analyzing...");
            m_analyzer->analyze();
            m_document->moveToEP();
        }).detach();
    }

    return true;
}

u32 DisassemblerAlgorithm::disassembleInstruction(address_t address, const InstructionPtr& instruction)
{
    if(!this->canBeDisassembled(address))
        return DisassemblerAlgorithm::SKIP;

    instruction->address = address;

    Buffer buffer = m_format->buffer() + m_format->offset(address);
    return m_assembler->decode(buffer, instruction) ? DisassemblerAlgorithm::OK : DisassemblerAlgorithm::FAIL;
}

void DisassemblerAlgorithm::onDecoded(const InstructionPtr &instruction)
{
    for(const Operand& op : instruction->operands)
    {
        if(!op.isNumeric())
            continue;

        if(instruction->is(InstructionTypes::Jump) && instruction->isTargetOperand(op))
        {
            if(op.is(OperandTypes::Memory))
                ENQUEUE_STATE(DisassemblerAlgorithm::AddressTableState, op.u_value, op.index, instruction);
            else
                ENQUEUE_STATE(DisassemblerAlgorithm::JumpState, op.u_value, op.index, instruction);
        }
        else if(instruction->is(InstructionTypes::Call) && instruction->isTargetOperand(op))
        {
            if(op.is(OperandTypes::Memory))
                ENQUEUE_STATE(DisassemblerAlgorithm::AddressTableState, op.u_value, op.index, instruction);
            else
                ENQUEUE_STATE(DisassemblerAlgorithm::CallState, op.u_value, op.index, instruction);
        }
        else
        {
            if(op.is(OperandTypes::Memory))
                ENQUEUE_STATE(DisassemblerAlgorithm::AddressTableState, op.u_value, op.index, instruction);
            else if(op.is(OperandTypes::Immediate))
                ENQUEUE_STATE(DisassemblerAlgorithm::ImmediateState, op.u_value, op.index, instruction);
        }
    }
}

void DisassemblerAlgorithm::onDecodeFailed(const InstructionPtr &instruction) { RE_UNUSED(instruction); }

void DisassemblerAlgorithm::decodeState(const State* state)
{
    InstructionPtr instruction = std::make_shared<Instruction>();
    u32 status = this->disassemble(state->address, instruction);

    if(status == DisassemblerAlgorithm::SKIP)
    {
        REDasm::status("Skipped @ " + REDasm::hex(state->address, m_format->bits(), false));
        return;
    }

    REDasm::status("Disassembled @ " + REDasm::hex(state->address, m_format->bits(), false));
    m_document->instruction(instruction);
}

void DisassemblerAlgorithm::jumpState(const State *state)
{
    int dir = BRANCH_DIRECTION(state->instruction, state->address);

    if(dir < 0)
        state->instruction->cmt("Possible loop");
    else if(!dir)
        state->instruction->cmt("Infinite loop");

    m_document->symbol(state->address, SymbolTypes::Code);
    m_disassembler->pushReference(state->address, state->instruction);
}

void DisassemblerAlgorithm::callState(const State *state)
{
    m_document->symbol(state->address, SymbolTypes::Function);
    m_disassembler->pushReference(state->address, state->instruction);
}

void DisassemblerAlgorithm::addressTableState(const State *state)
{
    const InstructionPtr& instruction = state->instruction;
    size_t targetstart = instruction->targets.size();
    int c = m_disassembler->checkAddressTable(instruction, state->address);

    if(c)
    {
        state_t fwdstate = DisassemblerAlgorithm::MemoryState;

        if(instruction->is(InstructionTypes::Call))
            fwdstate = DisassemblerAlgorithm::CallState;
        else if(instruction->is(InstructionTypes::Jump))
            fwdstate = DisassemblerAlgorithm::JumpState;

        size_t i = 0;

        for(address_t target : instruction->targets)
        {
            if(i >= targetstart)  // Skip decoded targets
                FORWARD_STATE_ADDRESS(fwdstate, target, state);

            i++;
        }
    }
    else
    {
        if(instruction->is(InstructionTypes::Jump))
            FORWARD_STATE(DisassemblerAlgorithm::JumpState, state);
        else if(instruction->is(InstructionTypes::Call))
            FORWARD_STATE(DisassemblerAlgorithm::CallState, state);
        else
            FORWARD_STATE(DisassemblerAlgorithm::MemoryState, state);
    }

    m_disassembler->pushReference(state->address, instruction);
}

void DisassemblerAlgorithm::memoryState(const State *state)
{
    const Operand& op = state->operand();
    u64 value = 0;

    if(op.isRead() && m_disassembler->dereference(state->address, &value))
    {
        m_document->symbol(state->address, SymbolTypes::Data | SymbolTypes::Pointer); // Create Symbol for pointer
        m_disassembler->pushReference(state->address, state->instruction);
        FORWARD_STATE_ADDRESS(DisassemblerAlgorithm::ImmediateState, value, state);
    }
    else
        FORWARD_STATE(DisassemblerAlgorithm::ImmediateState, state);
}

void DisassemblerAlgorithm::immediateState(const State *state)
{
    const REDasm::Segment* segment = m_document->segment(state->address);

    if(!segment)
        return;

    if(segment->is(SegmentTypes::Code))
        m_disassembler->checkString(state->instruction, state->address);   // Create Symbol + XRefs
    else if(segment->is(SegmentTypes::Data) || segment->is(SegmentTypes::Bss))
        m_disassembler->checkLocation(state->instruction, state->address); // Create Symbol + XRefs
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

void DisassemblerAlgorithm::createInvalidInstruction(const InstructionPtr &instruction)
{
    if(!instruction->size)
        instruction->size = 1; // Invalid instruction uses at least 1 byte

    instruction->type = InstructionTypes::Invalid;
    instruction->mnemonic = INVALID_MNEMONIC;

    if(!instruction->bytes.empty())
        return;

    Buffer buffer = m_format->buffer() + m_format->offset(instruction->address);

    std::stringstream ss;
    ss << std::hex << static_cast<size_t>(*buffer);
    instruction->bytes = ss.str();
}

u32 DisassemblerAlgorithm::disassemble(address_t address, const InstructionPtr &instruction)
{
    auto it = m_disassembled.find(address);

    if(it != m_disassembled.end())
        return DisassemblerAlgorithm::SKIP;

    m_disassembled.insert(address);
    u32 result = this->disassembleInstruction(address, instruction);

    if(result == DisassemblerAlgorithm::FAIL)
    {
        this->createInvalidInstruction(instruction);
        this->onDecodeFailed(instruction);
    }
    else
        this->onDecoded(instruction);

    return result;
}


} // namespace REDasm
