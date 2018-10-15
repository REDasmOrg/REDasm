#include "cil.h"

namespace REDasm {

CILAssembler::CILAssembler() { }
const char *CILAssembler::name() const { return "CIL/MSIL"; }
bool CILAssembler::decodeInstruction(Buffer buffer, const InstructionPtr &instruction) { return false; }

} // namespace REDasm
