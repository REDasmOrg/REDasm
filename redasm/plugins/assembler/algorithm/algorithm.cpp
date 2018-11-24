#include "algorithm.h"
#include "../../../plugins/format.h"
#include <thread>

#define INVALID_MNEMONIC "db"
#define ENQUEUE_DECODE_STATE(address) ENQUEUE_STATE(AssemblerAlgorithm::DecodeState, address, -1, NULL)

namespace REDasm {

AssemblerAlgorithm::AssemblerAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assembler): StateMachine(), m_disassembler(disassembler), m_assembler(assembler), m_currentsegment(NULL), m_analyzed(false)
{
    m_format = m_disassembler->format();
    m_document = m_disassembler->document();

    if(assembler->hasFlag(AssemblerFlags::HasEmulator))
        m_emulator = std::unique_ptr<Emulator>(assembler->createEmulator(disassembler));

    REGISTER_STATE(AssemblerAlgorithm::DecodeState, &AssemblerAlgorithm::decodeState);
    REGISTER_STATE(AssemblerAlgorithm::JumpState, &AssemblerAlgorithm::jumpState);
    REGISTER_STATE(AssemblerAlgorithm::CallState, &AssemblerAlgorithm::callState);
    REGISTER_STATE(AssemblerAlgorithm::BranchState, &AssemblerAlgorithm::branchState);
    REGISTER_STATE(AssemblerAlgorithm::BranchMemoryState, &AssemblerAlgorithm::branchMemoryState);
    REGISTER_STATE(AssemblerAlgorithm::AddressTableState, &AssemblerAlgorithm::addressTableState);
    REGISTER_STATE(AssemblerAlgorithm::MemoryState, &AssemblerAlgorithm::memoryState);
    REGISTER_STATE(AssemblerAlgorithm::ImmediateState, &AssemblerAlgorithm::immediateState);
    REGISTER_STATE(AssemblerAlgorithm::EraseSymbolState, &AssemblerAlgorithm::eraseSymbolState);
}

void AssemblerAlgorithm::enqueue(address_t address) { ENQUEUE_DECODE_STATE(address); }

bool AssemblerAlgorithm::analyze()
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

bool AssemblerAlgorithm::validateState(const State &state) const { return m_document->segment(state.address); }
void AssemblerAlgorithm::onNewState(const State &state) const { REDasm::status("Analyzing @ " + REDasm::hex(state.address, m_format->bits())); }

u32 AssemblerAlgorithm::disassembleInstruction(address_t address, const InstructionPtr& instruction)
{
    if(!this->canBeDisassembled(address))
        return AssemblerAlgorithm::SKIP;

    instruction->address = address;

    BufferRef buffer = m_format->buffer(address);
    return m_assembler->decode(buffer, instruction) ? AssemblerAlgorithm::OK : AssemblerAlgorithm::FAIL;
}

void AssemblerAlgorithm::onDecoded(const InstructionPtr &instruction)
{
    for(const Operand& op : instruction->operands)
    {
        if(!op.isNumeric() || op.displacementIsDynamic())
        {
            if(m_emulator && !m_emulator->hasError())
                this->emulateOperand(op, instruction);

            if(!op.is(OperandTypes::Displacement)) // Try static displacement analysis
                continue;
        }

        if(op.is(OperandTypes::Displacement))
        {
            if(op.displacementIsDynamic())
                ENQUEUE_STATE(AssemblerAlgorithm::AddressTableState, op.disp.displacement, op.index, instruction);
            else if(op.displacementCanBeAddress())
                ENQUEUE_STATE(AssemblerAlgorithm::MemoryState, op.disp.displacement, op.index, instruction);
        }
        else if(op.is(OperandTypes::Memory))
            ENQUEUE_STATE(AssemblerAlgorithm::MemoryState, op.u_value, op.index, instruction);
        else
            ENQUEUE_STATE(AssemblerAlgorithm::ImmediateState, op.u_value, op.index, instruction);

        this->onDecodedOperand(op, instruction);
    }
}

void AssemblerAlgorithm::onDecodeFailed(const InstructionPtr &instruction) { RE_UNUSED(instruction); }

void AssemblerAlgorithm::onDecodedOperand(const Operand &op, const InstructionPtr &instruction)
{
    RE_UNUSED(instruction);
    RE_UNUSED(op);
}

void AssemblerAlgorithm::onEmulatedOperand(const Operand &op, const InstructionPtr &instruction, u64 value)
{
    ENQUEUE_STATE(AssemblerAlgorithm::AddressTableState, value, op.index, instruction);
}

void AssemblerAlgorithm::decodeState(State *state)
{
    InstructionPtr instruction = std::make_shared<Instruction>();
    u32 status = this->disassemble(state->address, instruction);

    if(status == AssemblerAlgorithm::SKIP)
        return;

    m_document->instruction(instruction);
}

void AssemblerAlgorithm::jumpState(State *state)
{
    s64 dir = BRANCH_DIRECTION(state->instruction, state->address);

    if(!dir)
        m_document->comment(state->instruction->address, "Infinite loop");

    m_document->symbol(state->address, SymbolTypes::Code);
    m_disassembler->pushReference(state->address, state->instruction->address);
}

void AssemblerAlgorithm::callState(State *state)
{
    m_document->symbol(state->address, SymbolTypes::Function);
    m_disassembler->pushReference(state->address, state->instruction->address);
}

void AssemblerAlgorithm::branchState(State *state)
{
    InstructionPtr instruction = state->instruction;

    if(instruction->is(InstructionTypes::Call))
        FORWARD_STATE(AssemblerAlgorithm::CallState, state);
    else if(instruction->is(InstructionTypes::Jump))
        FORWARD_STATE(AssemblerAlgorithm::JumpState, state);
    else
        REDasm::log("Invalid branch state for instruction " + REDasm::quoted(instruction->mnemonic) + " @ "
                                                            + REDasm::hex(instruction->address, m_format->bits()));

}

void AssemblerAlgorithm::branchMemoryState(State *state)
{
    SymbolPtr symbol = m_document->symbol(state->address);

    if(symbol && symbol->isImport()) // Don't dereference imports
        return;

    u64 value = 0;
    m_disassembler->dereference(state->address, &value);
    m_document->symbol(state->address, SymbolTypes::Data | SymbolTypes::Pointer);

    InstructionPtr instruction = state->instruction;

    if(instruction->is(InstructionTypes::Call))
        m_document->symbol(value, SymbolTypes::Function);
    else
        m_document->symbol(value, SymbolTypes::Code);

    m_disassembler->pushReference(value, state->address);
}

void AssemblerAlgorithm::addressTableState(State *state)
{
    InstructionPtr instruction = state->instruction;
    size_t targetstart = instruction->targets.size();
    int c = m_disassembler->checkAddressTable(instruction, state->address);

    if(c > 1)
    {
        m_disassembler->pushReference(state->address, instruction->address);

        REDasm::log("Found address table @ " + REDasm::hex(state->address, m_format->bits()));
        state_t fwdstate = AssemblerAlgorithm::BranchState;

        if(instruction->is(InstructionTypes::Call))
            m_document->comment(instruction->address, "Call Table with " + std::to_string(c) + " cases(s)");
        else if(instruction->is(InstructionTypes::Jump))
            m_document->comment(instruction->address, "Jump Table with " + std::to_string(c) + " cases(s)");
        else
            fwdstate = AssemblerAlgorithm::MemoryState;

        size_t i = 0;

        for(address_t target : instruction->targets)
        {
            if(i >= targetstart)  // Skip decoded targets
                FORWARD_STATE_VALUE(fwdstate, target, state);

            i++;
        }

        return;
    }

    const Operand& op = state->operand();

    if(op.is(OperandTypes::Memory))
        FORWARD_STATE(AssemblerAlgorithm::MemoryState, state);
    else
        FORWARD_STATE(AssemblerAlgorithm::ImmediateState, state);
}

void AssemblerAlgorithm::memoryState(State *state)
{
    u64 value = 0;

    if(!m_disassembler->dereference(state->address, &value))
    {
        FORWARD_STATE(AssemblerAlgorithm::ImmediateState, state);
        return;
    }

    InstructionPtr instruction = state->instruction;

    if(instruction->is(InstructionTypes::Branch) && instruction->isTargetOperand(state->operand()))
    {
        FORWARD_STATE(AssemblerAlgorithm::BranchMemoryState, state);
        m_disassembler->pushReference(state->address, instruction->address);
    }
    else
    {
        m_document->symbol(state->address, SymbolTypes::Data | SymbolTypes::Pointer);
        m_disassembler->checkLocation(state->address, value); // Create Symbol + XRefs
    }

    m_disassembler->pushReference(state->address, instruction->address);
}

void AssemblerAlgorithm::immediateState(State *state)
{
    InstructionPtr instruction = state->instruction;

    if(instruction->is(InstructionTypes::Branch) && instruction->isTargetOperand(state->operand()))
        FORWARD_STATE(AssemblerAlgorithm::BranchState, state);
    else
        m_disassembler->checkLocation(instruction->address, state->address); // Create Symbol + XRefs
}

void AssemblerAlgorithm::eraseSymbolState(State *state) { m_document->eraseSymbol(state->address); }

bool AssemblerAlgorithm::canBeDisassembled(address_t address)
{
    BufferRef buffer = m_format->buffer(address);

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

void AssemblerAlgorithm::createInvalidInstruction(const InstructionPtr &instruction)
{
    if(!instruction->size)
        instruction->size = 1; // Invalid instruction uses at least 1 byte

    instruction->type = InstructionTypes::Invalid;
    instruction->mnemonic = INVALID_MNEMONIC;
}

u32 AssemblerAlgorithm::disassemble(address_t address, const InstructionPtr &instruction)
{
    auto it = m_disassembled.find(address);

    if(it != m_disassembled.end())
        return AssemblerAlgorithm::SKIP;

    m_disassembled.insert(address);
    u32 result = this->disassembleInstruction(address, instruction);

    if(result == AssemblerAlgorithm::FAIL)
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

void AssemblerAlgorithm::emulateOperand(const Operand &op, const InstructionPtr &instruction)
{
    u64 value = 0;

    if(op.is(OperandTypes::Register))
    {
        if(!m_emulator->read(op, &value))
            return;
    }
    else if(op.is(OperandTypes::Displacement))
    {
        if(!m_emulator->displacement(op, &value))
            return;
    }
    else
        return;

    this->onEmulatedOperand(op, instruction, value);
}

void AssemblerAlgorithm::emulate(const InstructionPtr &instruction)
{
    if(!m_emulator)
        return;

    m_emulator->emulate(instruction);
}


} // namespace REDasm
