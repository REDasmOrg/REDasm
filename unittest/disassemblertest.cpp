#include "disassemblertest.h"
#include "redasm/disassembler/disassembler.h"
#include <iostream>
#include <QString>
#include <QFileInfo>
#include <QFile>
#include <QDir>

#define TEST_PREFIX                      "/home/davide/Programmazione/Campioni/" // NOTE: Yes, hardcoded for now :(
#define TEST_PATH(s)                     TEST_PREFIX + std::string(s)

#define REPEAT_COUNT                     20
#define REPEATED(s)                      std::string(REPEAT_COUNT, s)

#define RED_STRING(s)                    ("\x1b[31m" + std::string(s) + "\x1b[0m")
#define GREEN_STRING(s)                  ("\x1b[32m" + std::string(s) + "\x1b[0m")
#define TEST_OK                          GREEN_STRING("OK")
#define TEST_FAIL                        RED_STRING("FAIL")

#define TEST(s, cond)                    cout << "->> " << s << "..." << ((cond) ? TEST_OK : TEST_FAIL) << endl
#define TITLE(t)                         cout << REPEATED('-') << t << " " << REPEATED('-') << endl
#define TEST_TITLE(t)                    TITLE("Testing " << t)

#define TEST_NAME(sym, s)                (sym->name == s)
#define TEST_SYMBOL(s, sym, exp)         TEST(s, (sym && exp))
#define TEST_SYMBOL_NAME(s, sym, exp, n) TEST_SYMBOL(s, sym, TEST_NAME(sym, n) && exp)

#define ADD_TEST(t, cb)                  this->_tests[t] = [this](REDasm::Disassembler* disassembler) { this->cb(disassembler); }
#define ADD_TEST_NULL(t, cb)             this->_tests[t] = NULL;
#define ADD_TEST_PATH(t, cb)             this->_tests[TEST_PATH(t)] = [this](REDasm::Disassembler* disassembler) { this->cb(disassembler); }
#define ADD_TEST_PATH_NULL(t, cb)        this->_tests[TEST_PATH(t)] = NULL;

using namespace std;
using namespace REDasm;

DisassemblerTest::DisassemblerTest()
{
    ADD_TEST("/home/davide/Reversing/Cavia.exe", testCavia);

    ADD_TEST_PATH("PE Test/CM01.exe", testCM01);
    ADD_TEST_PATH("PE Test/VB5CRKME.EXE", testVB5CrackMe);
    ADD_TEST_PATH("PE Test/OllyDump.dll", testOllyDump);
    ADD_TEST_PATH("PE Test/tn_11.exe", testJumpTables);
    ADD_TEST_PATH("IOLI-crackme/bin-pocketPC/crackme0x01.arm.exe", testIoliARM);
    ADD_TEST_PATH("PE Test/tn12/scrack.exe", testSCrack);

    ADD_TEST_PATH_NULL("PE Test/CorruptedIT.exe", NULL);

}

void DisassemblerTest::runTests()
{
    REDasm::setLoggerCallback([](const std::string&) { });
    REDasm::init(QDir::currentPath().toStdString());

    std::for_each(this->_tests.begin(), this->_tests.end(), [](const TestItem& test) {
        QString testpath = QString::fromStdString(test.first);
        QFileInfo fi(testpath);

        if(!fi.exists()) {
            cout << "!!! SKIPPING TEST '" << qUtf8Printable(fi.fileName()) << "', file not found..." << endl << endl;
            return;
        }

        TEST_TITLE(qUtf8Printable(fi.fileName()));
        QByteArray data = DisassemblerTest::readFile(testpath);

        if(data.isEmpty()) {
            cout << "!!! File is empty" << endl << endl;
            return;
        }

        DisassemblerTest::runTest(data, test.second);
        cout << REPEATED('-') << REPEATED('-') << REPEATED('-') << endl << endl;
    });
}

string DisassemblerTest::replaceAll(std::string str, const std::string &from, const std::string &to)
{
    if(from.empty())
        return str;

    size_t idx = 0;

    while((idx = str.find(from, idx)) != std::string::npos)
    {
        str.replace(idx, from.length(), to);
        idx += to.length();
    }

    return str;
}

QByteArray DisassemblerTest::readFile(const QString &file)
{
    QFile f(file);

    if(!f.open(QFile::ReadOnly))
        return QByteArray();

    QByteArray ba = f.readAll();
    f.close();
    return ba;
}

void DisassemblerTest::runTest(QByteArray &data, const TestCallback& testcallback)
{
    FormatPlugin* format = REDasm::getFormat(reinterpret_cast<u8*>(data.data()), data.length());
    TEST("Format", format);

    if(!format)
        return;

    AssemblerPlugin* assembler = REDasm::getAssembler(format->assembler());
    TEST("Assembler", assembler);

    if(!assembler)
        return;

    Buffer buffer(data.data(), data.length());
    Disassembler disassembler(buffer, assembler, format);

    cout << "->> Disassembler...";
        disassembler.disassemble();
    cout << TEST_OK << endl;

    if(testcallback)
        testcallback(&disassembler);
}

void DisassemblerTest::testVBEvents(Disassembler *disassembler, const std::map<address_t, string> &vbevents)
{
    SymbolTable* symboltable = disassembler->symbolTable();
    SymbolPtr symbol;

    std::for_each(vbevents.begin(), vbevents.end(), [this, symboltable, &symbol](const std::pair<address_t, std::string>& vbevent) {
        std::string procname = DisassemblerTest::replaceAll(vbevent.second, "::", "_");
        symbol = symboltable->symbol(vbevent.first);

        TEST_SYMBOL_NAME("Event " + vbevent.second + " @ " + REDasm::hex(vbevent.first, 0, false),
                         symbol, symbol->is(SymbolTypes::Function), procname);
    });
}

void DisassemblerTest::testCavia(REDasm::Disassembler *disassembler)
{
    SymbolTable* symboltable = disassembler->symbolTable();

    SymbolPtr symbol = symboltable->symbol(0x00401000);
    TEST_SYMBOL("EntryPoint", symbol, symbol->isFunction());

    symbol = symboltable->symbol(0x00401029);
    TEST_SYMBOL_NAME("WndProc", symbol, symbol->isFunction(), "DlgProc_401029");
}

void DisassemblerTest::testCM01(Disassembler *disassembler)
{
    SymbolTable* symboltable = disassembler->symbolTable();

    SymbolPtr symbol = symboltable->symbol(0x00401128);
    TEST_SYMBOL_NAME("Exported WndProc", symbol, symbol->isFunction() && symbol->is(SymbolTypes::ExportFunction), "WndProc");

    symbol = symboltable->symbol(0x00401253);
    TEST_SYMBOL_NAME("DlgProc @ 00401253", symbol, symbol->isFunction(), "DlgProc_401253");

    symbol = symboltable->symbol(0x0040130A);
    TEST_SYMBOL_NAME("DlgProc @ 0040130A", symbol, symbol->isFunction(), "DlgProc_40130A");

    symbol = symboltable->symbol(0x004020E7);
    TEST_SYMBOL("Ascii String @ 004020E7", symbol, symbol->is(SymbolTypes::String));

    symbol = symboltable->symbol(0x00402129);
    TEST_SYMBOL("Ascii String @ 00402129", symbol, symbol->is(SymbolTypes::String));

    symbol = symboltable->symbol(0x00402134);
    TEST_SYMBOL("Ascii String @ 00402134", symbol, symbol->is(SymbolTypes::String));
}

void DisassemblerTest::testOllyDump(Disassembler *disassembler)
{
    SymbolTable* symboltable = disassembler->symbolTable();
    Listing& listing = disassembler->listing();

    SymbolPtr symbol = symboltable->symbol(0x00403bdc);
    TEST_SYMBOL("Checking Function @ 00403bdc", symbol, symbol->isFunction());

    auto it = listing.find(0x00403bea);
    TEST("Checking CALL @ 0x00403bea", it != listing.end());

    if(it == listing.end())
        return;

    InstructionPtr instruction = *it;
    TEST("Validating CALL @ 0x00403bea target", instruction->is(InstructionTypes::Call) && instruction->hasTargets());

    symbol = symboltable->symbol(instruction->target());
    TEST_SYMBOL("Checking if target a data-pointer", symbol, symbol->is(SymbolTypes::Pointer) && symbol->is(SymbolTypes::Data));

    symbol = disassembler->dereferenceSymbol(symbol);
    TEST_SYMBOL("Checking if dereferenced pointer is a function", symbol, symbol->isFunction());
}

void DisassemblerTest::testSCrack(Disassembler *disassembler)
{
    SymbolTable* symboltable = disassembler->symbolTable();

    SymbolPtr symbol = symboltable->symbol(0x004013E4);
    TEST_SYMBOL_NAME("Import VB6 ThunRTMain", symbol, symbol->is(SymbolTypes::Function), "_msvbvm60_dll_ThunRTMain");

    symbol = symboltable->symbol(0x00402b1c);
    TEST_SYMBOL("Wide String @ 0x00402b1c", symbol, symbol->is(SymbolTypes::WideString));

    symbol = symboltable->symbol(0x00402b2c);
    TEST_SYMBOL("Wide String @ 0x00402b2c", symbol, symbol->is(SymbolTypes::WideString));

    std::map<address_t, std::string> vbevents;
    vbevents[0x00403BB0] = "main::about::Click";
    vbevents[0x00403D20] = "main::about::GotFocus";
    vbevents[0x00403DE0] = "main::about::LostFocus";
    vbevents[0x00403EA0] = "main::register::Click";
    vbevents[0x00404970] = "main::register::GotFocus";
    vbevents[0x00404A30] = "main::register::LostFocus";
    vbevents[0x00404AF0] = "main::sn::GotFocus";
    vbevents[0x00404BB0] = "main::sn::LostFocus";
    vbevents[0x00404C70] = "main::uname::GotFocus";
    vbevents[0x00404D30] = "main::uname::LostFocus";
    vbevents[0x00404DF0] = "aboutfrm::ok::Click";
    vbevents[0x00404EE0] = "aboutfrm::pmode::Click";
    vbevents[0x00404FE0] = "aboutfrm::uic::Click";

    this->testVBEvents(disassembler, vbevents);
}

void DisassemblerTest::testVB5CrackMe(Disassembler *disassembler)
{
    SymbolTable* symboltable = disassembler->symbolTable();

    SymbolPtr symbol = symboltable->symbol(0x0040110E);
    TEST_SYMBOL_NAME("Import VB5 ThunRTMain", symbol, symbol->is(SymbolTypes::Function), "_msvbvm50_dll_ThunRTMain");

    symbol = symboltable->symbol(0x00401EB8);
    TEST_SYMBOL("Wide String @ 0x00401EB8", symbol, symbol->is(SymbolTypes::WideString));

    symbol = symboltable->symbol(0x00401EF8);
    TEST_SYMBOL("Wide String @ 0x00401EF8", symbol, symbol->is(SymbolTypes::WideString));

    symbol = symboltable->symbol(0x00401F08);
    TEST_SYMBOL("Wide String @ 0x00401F08", symbol, symbol->is(SymbolTypes::WideString));

    symbol = symboltable->symbol(0x00401F44);
    TEST_SYMBOL("Wide String @ 0x00401F44", symbol, symbol->is(SymbolTypes::WideString));

    std::map<address_t, std::string> vbevents;
    vbevents[0x004020C4] = "Form1::Command1::Click";

    this->testVBEvents(disassembler, vbevents);
}

void DisassemblerTest::testIoliARM(Disassembler *disassembler)
{
    SymbolTable* symboltable = disassembler->symbolTable();
    Listing& listing = disassembler->listing();

    auto it = listing.find(0x00011064);
    TEST("Checking LDR @ 0x00011064", it != listing.end());

    if(it == listing.end())
        return;

    InstructionPtr instruction = *it;
    TEST("Checking LDR's operands count", (instruction->mnemonic == "ldr") && (instruction->operands.size() >= 2));

    Operand op = instruction->operands[1];
    TEST("Checking LDR's operand 2", op.is(OperandTypes::Memory));

    SymbolPtr symbol = symboltable->symbol(op.u_value);
    TEST_SYMBOL("Checking LDR's operand 2 symbol", symbol, symbol->is(SymbolTypes::Data) && symbol->is(SymbolTypes::Pointer));

    symbol = disassembler->dereferenceSymbol(symbol);
    TEST_SYMBOL("Checking LDR's operand 2 dereferenced string", symbol, symbol->is(SymbolTypes::String));

    it = listing.find(0x00011088);
    TEST("Checking LDR @ 0x00011088", it != listing.end());

    if(it == listing.end())
        return;

    u64 value = 0;
    instruction = *it;
    TEST("Checking LDR's operands count", (instruction->mnemonic == "ldr") && (instruction->operands.size() >= 2));

    op = instruction->operands[1];
    TEST("Checking LDR's operand 2", op.is(OperandTypes::Memory));

    symbol = symboltable->symbol(op.u_value);
    TEST_SYMBOL("Checking LDR's operand 2 symbol", symbol, symbol->is(SymbolTypes::Data) && symbol->is(SymbolTypes::Pointer));
    TEST("Checking dereferenced value", disassembler->dereferencePointer(symbol->address, &value) && (value == 0x149a));
}

void DisassemblerTest::testJumpTables(Disassembler *disassembler)
{
    SymbolTable* symboltable = disassembler->symbolTable();
    Listing& listing = disassembler->listing();

    auto it = listing.find(0x00401197);
    TEST("Checking JUMP TABLE @ 0x00401197", it != listing.end());

    InstructionPtr instruction = *it;
    TEST("Checking TARGETS count @ 0x00401197", instruction->targets.size() == 5);

    if(instruction->targets.size() != 5)
        return;

    size_t i = 0;

    std::for_each(instruction->targets.begin(), instruction->targets.end(), [this, &symboltable, &listing, &i](address_t target) {
        SymbolPtr symbol = symboltable->symbol(target);
        auto iit = listing.find(target);

        TEST("Checking CASE #" + std::to_string(i) + " @ " + REDasm::hex(target), symbol && symbol->is(SymbolTypes::Code) && iit != listing.end());
        i++;
    });
}
