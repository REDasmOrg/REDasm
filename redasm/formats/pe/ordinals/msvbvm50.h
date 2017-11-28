#ifndef MSVBVM50_H
#define MSVBVM50_H

#include "pe_ordinals_types.h"

namespace REDasm {

class MSVBVM50
{
    public:
        MSVBVM50();

    public:
        static void compile(OrdinalMap& m);
};

} // namespace REDasm

#endif // MSVBVM50_H
