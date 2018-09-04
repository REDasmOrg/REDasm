#ifndef INSTRUCTIONPOOL_H
#define INSTRUCTIONPOOL_H

#include "../../support/cachemap.h"
#include "../../redasm.h"

namespace REDasm {

class FormatPlugin;

class InstructionPool: public cache_map<address_t, InstructionPtr>
{
    public:
        InstructionPool();
        virtual ~InstructionPool();
        void update(const InstructionPtr &instruction);

    protected:
        virtual void serialize(const InstructionPtr &value, std::fstream &fs);
        virtual void deserialize(InstructionPtr &value, std::fstream &fs);
};

}

#endif // INSTRUCTIONPOOL_H
