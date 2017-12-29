#ifndef DALVIK_H
#define DALVIK_H

#include "../../plugins/plugins.h"

namespace REDasm {

class DalvikProcessor : public ProcessorPlugin
{
    public:
        DalvikProcessor();
        virtual const char* name() const;
};

DECLARE_PROCESSOR_PLUGIN(DalvikProcessor, dalvik)

} // namespace REDasm

#endif // DALVIK_H
