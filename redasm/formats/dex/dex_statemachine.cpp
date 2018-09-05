#include "dex_statemachine.h"
#include "dex_utils.h"

#define DBG_FIRST_SPECIAL 0x0A // the smallest special opcode
#define DBG_LINE_BASE     -4   // The smallest line number increment
#define DBG_LINE_RANGE    15   // The number of line increments represented

#define BIND_STATE(opcode)   m_statesmap[opcode] = [this](u8** data) { this->execute##opcode(data); }
#define VALIDATE_LINE()      if(m_line == 0) REDasm::log("WARNING: line register == 0")

namespace REDasm {

DEXStateMachine::DEXStateMachine(u16 address, DEXDebugInfo &debuginfo): m_debuginfo(debuginfo), m_address(address), m_line(debuginfo.line_start), m_atend(false)
{
    BIND_STATE(0x00);
    BIND_STATE(0x01);
    BIND_STATE(0x02);
    BIND_STATE(0x03);
    BIND_STATE(0x04);
    BIND_STATE(0x05);
    BIND_STATE(0x06);
    BIND_STATE(0x07);
    BIND_STATE(0x08);
    BIND_STATE(0x09);
}

void DEXStateMachine::execute(u8 *data)
{
    while(!m_atend)
    {
        u8 opcode = *data;
        data++;

        if(opcode >= DBG_FIRST_SPECIAL)
        {
            this->executeSpecial(opcode);
            continue;
        }

        auto it = m_statesmap.find(opcode);

        if(it == m_statesmap.end())
        {
            REDasm::log("Unknown opcode '" + REDasm::hex(opcode) + "'");
            return;
        }

        it->second(&data);
    }
}

void DEXStateMachine::execute0x00(u8 **data) // DBG_END_SEQUENCE
{
    RE_UNUSED(data);

    m_atend = true;
}

void DEXStateMachine::execute0x01(u8 **data) // DBG_ADVANCE_PC
{
    m_address += DEXUtils::getULeb128(data);
}

void DEXStateMachine::execute0x02(u8 **data) // DBG_ADVANCE_LINE
{
    m_line += DEXUtils::getSLeb128(data);
    VALIDATE_LINE();
}

void DEXStateMachine::execute0x03(u8 **data) // DBG_START_LOCAL
{
    u32 r = DEXUtils::getULeb128(data);
    s32 n = DEXUtils::getULeb128p1(data), t = DEXUtils::getULeb128p1(data);

    this->setDebugData(DEXDebugData::local(r, n, t));
}

void DEXStateMachine::execute0x04(u8 **data) // DBG_START_LOCAL_EXTENDED
{
    u32 r = DEXUtils::getULeb128(data);
    s32 n = DEXUtils::getULeb128p1(data), t = DEXUtils::getULeb128p1(data), s = DEXUtils::getULeb128p1(data);

    this->setDebugData(DEXDebugData::localext(r, n, t, s));
}

void DEXStateMachine::execute0x05(u8 **data) // DBG_END_LOCAL
{
    RE_UNUSED(data);
    this->setDebugData(DEXDebugData::endLocal(DEXUtils::getULeb128(data)));
}

void DEXStateMachine::execute0x06(u8 **data) // DBG_RESTART_LOCAL
{
    RE_UNUSED(data);
    this->setDebugData(DEXDebugData::restartLocal(DEXUtils::getULeb128(data)));
}

void DEXStateMachine::execute0x07(u8 **data) // DBG_SET_PROLOGUE_END
{
    RE_UNUSED(data);
    this->setDebugData(DEXDebugData::prologueEnd());
}

void DEXStateMachine::execute0x08(u8 **data) // DBG_SET_EPILOGUE_BEGIN
{
    RE_UNUSED(data);
    this->setDebugData(DEXDebugData::epilogueBegin());
}

void DEXStateMachine::execute0x09(u8 **data) // DBG_SET_FILE
{
    this->setDebugData(DEXDebugData::file(DEXUtils::getULeb128p1(data)));
}

void DEXStateMachine::executeSpecial(u8 opcode) // Special opcodes
{
    u16 adjopcode = opcode - DBG_FIRST_SPECIAL;
    m_line += DBG_LINE_BASE + (adjopcode % DBG_LINE_RANGE);
    m_address += (adjopcode / DBG_LINE_RANGE) * sizeof(u16);

    VALIDATE_LINE();
    this->setDebugData(DEXDebugData::line(m_line));
}

void DEXStateMachine::setDebugData(const DEXDebugData &debugdata)
{
    auto it = m_debuginfo.debug_data.find(m_address);

    if(it == m_debuginfo.debug_data.end())
    {
        std::list<DEXDebugData> dbgdatalist;
        dbgdatalist.push_back(debugdata);
        m_debuginfo.debug_data[m_address] = dbgdatalist;
    }
    else
        it->second.push_back(debugdata);
}

} // namespace REDasm
