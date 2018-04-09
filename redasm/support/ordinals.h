#ifndef ORDINALS_H
#define ORDINALS_H

#include "../redasm.h"

namespace REDasm {

typedef std::unordered_map<u64, std::string> OrdinalsMap;

bool loadordinals(const std::string& ordinalfile, OrdinalsMap& ordinals);
std::string ordinal(const OrdinalsMap& ordinals, u64 ordinal, const std::string& fallbackprefix = std::string());

} // namespace REDasm

#endif // ORDINALS_H
