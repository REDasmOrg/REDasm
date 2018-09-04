#ifndef DEX_STATEMACHINE_H
#define DEX_STATEMACHINE_H

// https://source.android.com/devices/tech/dalvik/dex-format#debug-info-item

#include "../../redasm.h"
#include "dex_header.h"

namespace REDasm {


class DEXStateMachine
{
    private:
        enum States: u8 { DbgEndSequence = 0, DbgAdvancePc, DbgAdvanceLine, DbgStartLocal,
                          DbgStartLocalExtended, DbgEndLocal, DbgRestartLocal,
                          DbgSetPrologueEnd, DbgSetEpilogueBegin, DbgSetFile,
                          DbgFirstSpecial, DbgLastSpecial = 0xFF };

        typedef std::function<void(u8**)> StateCallback;
        typedef std::unordered_map<u8, StateCallback> StatesMap;

    public:
        DEXStateMachine(u16 address, DEXDebugInfo& debuginfo);
        void execute(u8* data);

    private:
        void execute0x00(u8** data);
        void execute0x01(u8** data);
        void execute0x02(u8** data);
        void execute0x03(u8** data);
        void execute0x04(u8** data);
        void execute0x05(u8** data);
        void execute0x06(u8** data);
        void execute0x07(u8** data);
        void execute0x08(u8** data);
        void execute0x09(u8** data);
        void executeSpecial(u8 opcode);

    private:
        void setDebugData(const DEXDebugData& debugdata);

    private:
        StatesMap m_statesmap;
        DEXDebugInfo& m_debuginfo;
        u16 m_address;
        u32 m_line;
        bool m_atend;
};

} // namespace REDasm

#endif // DEX_STATEMACHINE_H
