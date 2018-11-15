#ifndef REDASM_RUNTIME_H
#define REDASM_RUNTIME_H

#include <functional>
#include <string>

namespace REDasm {
namespace Runtime {

typedef std::function<void(const std::string&)> LogCallback;

extern std::string rntSearchPath;
extern std::string rntDirSeparator;
extern LogCallback rntLogCallback;
extern LogCallback rntStatusCallback;

} // namespace Runtime
} // namespace REDasm

#endif // REDASM_RUNTIME_H
