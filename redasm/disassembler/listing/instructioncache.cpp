#include "instructioncache.h"
#include "../../support/serializer.h"
#include "../../plugins/format.h"

namespace REDasm {

InstructionCache::InstructionCache(): cache_map<address_t, InstructionPtr>("instructions") { }
void InstructionCache::update(const InstructionPtr &instruction) { this->commit(instruction->address, instruction); }

void InstructionCache::serialize(const InstructionPtr &value, std::fstream &fs)
{
    Serializer::serializeScalar(fs, value->address);
    Serializer::serializeScalar(fs, value->target_idx);
    Serializer::serializeScalar(fs, value->type);
    Serializer::serializeScalar(fs, value->size);
    Serializer::serializeScalar(fs, value->id);
    Serializer::serializeString(fs, value->mnemonic);

    Serializer::serializeArray<std::set, address_t>(fs, value->targets, [&](address_t target) {
        Serializer::serializeScalar(fs, target);
    });

    Serializer::serializeArray<std::vector, Operand>(fs, value->operands, [&](const Operand& op) {
        Serializer::serializeScalar(fs, op.loc_index);
        Serializer::serializeScalar(fs, op.type);
        Serializer::serializeScalar(fs, op.extra_type);
        Serializer::serializeScalar(fs, op.size);
        Serializer::serializeScalar(fs, op.index);

        Serializer::serializeScalar(fs, op.reg.extra_type);
        Serializer::serializeScalar(fs, op.reg.r);

        Serializer::serializeScalar(fs, op.disp.base);
        Serializer::serializeScalar(fs, op.disp.index);
        Serializer::serializeScalar(fs, op.disp.scale);
        Serializer::serializeScalar(fs, op.disp.displacement);

        Serializer::serializeScalar(fs, op.u_value);
    });
}

void InstructionCache::deserialize(InstructionPtr &value, std::fstream &fs)
{
    value = std::make_shared<Instruction>();

    Serializer::deserializeScalar(fs, &value->address);
    Serializer::deserializeScalar(fs, &value->target_idx);
    Serializer::deserializeScalar(fs, &value->type);
    Serializer::deserializeScalar(fs, &value->size);
    Serializer::deserializeScalar(fs, &value->id);
    Serializer::deserializeString(fs, value->mnemonic);

    Serializer::deserializeArray<std::set, address_t>(fs, value->targets, [&](address_t& target) {
        Serializer::deserializeScalar(fs, &target);
    });

    Serializer::deserializeArray<std::vector, Operand>(fs, value->operands, [&](Operand& op) {
        Serializer::deserializeScalar(fs, &op.loc_index);
        Serializer::deserializeScalar(fs, &op.type);
        Serializer::deserializeScalar(fs, &op.extra_type);
        Serializer::deserializeScalar(fs, &op.size);
        Serializer::deserializeScalar(fs, &op.index);

        Serializer::deserializeScalar(fs, &op.reg.extra_type);
        Serializer::deserializeScalar(fs, &op.reg.r);

        Serializer::deserializeScalar(fs, &op.disp.base);
        Serializer::deserializeScalar(fs, &op.disp.index);
        Serializer::deserializeScalar(fs, &op.disp.scale);
        Serializer::deserializeScalar(fs, &op.disp.displacement);

        Serializer::deserializeScalar(fs, &op.u_value);
    });
}

}
