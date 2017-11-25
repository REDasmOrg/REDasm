#ifndef MSVBVM_H
#define MSVBVM_H

#include "pe_ordinals_types.h"

namespace REDasm {

class MSVBVM
{
    private:
        MSVBVM();

    public:
        static void compile(OrdinalMap& m);
};

} // namespace REDasm

#endif // MSVBVM_H
