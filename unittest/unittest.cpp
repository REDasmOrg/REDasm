#include "unittest.h"
#include "disassemblertest.h"
#include <core/redasm_context.h>

int UnitTest::run()
{
    REDasm::Context::sync(true);
    DisassemblerTest disasmtest;
    disasmtest.runTests();
    return 0;
}
