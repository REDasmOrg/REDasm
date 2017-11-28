#ifndef MSVBVM60_H
#define MSVBVM60_H

#include "pe_ordinals_types.h"

namespace REDasm {

class MSVBVM60
{
    private:
        MSVBVM60();

    public:
        static void compile(OrdinalMap& m);
};

} // namespace REDasm

#endif // MSVBVM_H
