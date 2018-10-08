#include "unittest.h"
#include "disassemblertest.h"

int UnitTest::run()
{
    putenv("SYNC_MODE=1");

    DisassemblerTest disasmtest;
    disasmtest.runTests();
    return 0;
}
