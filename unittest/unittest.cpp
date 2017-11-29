#include "unittest.h"
#include "disassemblertest.h"

int UnitTest::run()
{
    DisassemblerTest disasmtest;
    disasmtest.runTests();
    return 0;
}
