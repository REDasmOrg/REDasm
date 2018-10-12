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

    if(assembler->hasFlag(AssemblerFlags::HasEmulator))
        m_emulator = std::make_unique<Emulator>(assembler->createEmulator(disassembler));

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

bool DisassemblerAlgorithm::validateState(const State &state) const { return m_document->segment(state.address); }

void DisassemblerAlgorithm::onNewState(const State &state) const
{
    REDasm::status("Analyzing @ " + REDasm::hex(state.address, m_format->bits(), false));
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
        if(!op.isNumeric() || op.displacementIsDynamic())
        {
            if(m_emulator && !m_emulator->hasError())
                this->onEmulatedOperand(instruction, op);
            else if(!op.is(OperandTypes::Displacement)) // Try "displacementCanBeAddress" state
                continue;
        }

        if(op.is(OperandTypes::Displacement) && op.displacementCanBeAddress())
            ENQUEUE_STATE(DisassemblerAlgorithm::AddressTableState, op.disp.displacement, op.index, instruction);
        else if(op.is(OperandTypes::Memory))
            ENQUEUE_STATE(DisassemblerAlgorithm::AddressTableState, op.u_value, op.index, instruction);
        else
            ENQUEUE_STATE(DisassemblerAlgorithm::ImmediateState, op.u_value, op.index, instruction);

        this->onDecodedOperand(instruction, op);
    }
}

void DisassemblerAlgorithm::onDecodedOperand(const InstructionPtr &instruction, const Operand &op)
{
    RE_UNUSED(instruction);
    RE_UNUSED(op);
}

void DisassemblerAlgorithm::onDecodeFailed(const InstructionPtr &instruction) { RE_UNUSED(instruction); }

void DisassemblerAlgorithm::onEmulatedOperand(const InstructionPtr &instruction, const Operand &op)
{
    u64 value = 0;

    if(op.is(OperandTypes::Register))
    {
        if(!m_emulator->read(op, &value))
            return;
    }
    else if(op.is(OperandTypes::Displacement))
    {
        if(!m_emulator->computeDisplacement(op, &value))
            return;
    }
    else
        return;

    ENQUEUE_STATE(DisassemblerAlgorithm::AddressTableState, value, op.index, instruction);
}

void DisassemblerAlgorithm::decodeState(const State* state)
{
    InstructionPtr instruction = std::make_shared<Instruction>();
    u32 status = this->disassemble(state->address, instruction);

    if(status == DisassemblerAlgorithm::SKIP)
        return;

    m_document->instruction(instruction);
}

void DisassemblerAlgorithm::jumpState(const State *state)
{
    int dir = BRANCH_DIRECTION(state->instruction, state->address);

    if(dir < 0)
        m_document->comment(state->instruction, "Possible loop");
    else if(!dir)
        m_document->comment(state->instruction, "Infinite loop");

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

    if(c > 1)
    {
        m_disassembler->pushReference(state->address, instruction);

        REDasm::log("Found address table @ " + REDasm::hex(state->address, m_format->bits(), false));
        state_t fwdstate = DisassemblerAlgorithm::MemoryState;

        if(instruction->is(InstructionTypes::Call))
        {
            fwdstate = DisassemblerAlgorithm::CallState;
            m_document->comment(instruction, "Call Table with " + std::to_string(c) + " cases(s)");
        }
        else if(instruction->is(InstructionTypes::Jump))
        {
            fwdstate = DisassemblerAlgorithm::JumpState;
            m_document->comment(instruction, "Jump Table with " + std::to_string(c) + " cases(s)");
        }

        size_t i = 0;

        for(address_t target : instruction->targets)
        {
            if(i >= targetstart)  // Skip decoded targets
                FORWARD_STATE_ADDRESS(fwdstate, target, state);

            i++;
        }

        return;
    }

    const Operand& op = state->operand();

    if(op.is(OperandTypes::Memory))
        FORWARD_STATE(DisassemblerAlgorithm::MemoryState, state);
    else
        FORWARD_STATE(DisassemblerAlgorithm::ImmediateState, state);
}

void DisassemblerAlgorithm::memoryState(const State *state)
{
    u64 value = 0;

    if(m_disassembler->dereference(state->address, &value))
    {
        m_document->symbol(state->address, SymbolTypes::Data | SymbolTypes::Pointer); // Create Symbol for pointer
        m_disassembler->pushReference(state->address, state->instruction);
        FORWARD_STATE_ADDRESS(DisassemblerAlgorithm::ImmediateState, value, state);
        return;
    }

    FORWARD_STATE(DisassemblerAlgorithm::ImmediateState, state);
}

void DisassemblerAlgorithm::immediateState(const State *state)
{
    const InstructionPtr instruction = state->instruction;

    if(instruction->is(InstructionTypes::Jump) && instruction->isTargetOperand(state->operand()))
        FORWARD_STATE(DisassemblerAlgorithm::JumpState, state);
    else if(instruction->is(InstructionTypes::Call) && instruction->isTargetOperand(state->operand()))
        FORWARD_STATE(DisassemblerAlgorithm::CallState, state);
    else
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
    {
        this->emulate(instruction);
        this->onDecoded(instruction);
    }

    return result;
}

void DisassemblerAlgorithm::emulate(const InstructionPtr &instruction)
{
    if(!m_emulator)
        return;

    m_emulator->emulate(instruction);
}


} // namespace REDasm
