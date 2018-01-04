#ifndef DEX_STATEMACHINE_H
#define DEX_STATEMACHINE_H

// https://source.android.com/devices/tech/dalvik/dex-format#debug-info-item

#include "../../redasm.h"

namespace REDasm {

class DEXStateMachine
{
    private:
        enum States: u8 { DbgEndSequence = 0, DbgAdvancePc, DbgAdvanceLine, DbgStartLocal,
                          DbgStartLocalExtended, DbgEndLocal, DbgRestartLocal,
                          DbgSetPrologueEnd, DbgSetEpilogueBegin, DbgSetFile,
                          DbgFirstSpecial, DbgLastSpecial = 0xFF };

        typedef std::function<void()> StateCallback;
        typedef std::unordered_map<u8, StateCallback> StatesMap;

    public:
        DEXStateMachine();
        void execute(u8* data);

    private:
        StatesMap _statesmap;
};

} // namespace REDasm

#endif // DEX_STATEMACHINE_H
