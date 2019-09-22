#include "unittest.h"
#include "disassemblertest.h"
//#include <redasm/context.h>

int UnitTest::run()
{
    //r_ctx->sync(true);
    DisassemblerTest disasmtest;
    disasmtest.runTests();
    return 0;
}
