#include "disassemblertest.h"
#include "redasm/disassembler/disassembler.h"
#include <iostream>
#include <QString>
#include <QFileInfo>
#include <QFile>

#define TEST_PREFIX                      "/home/davide/Programmazione/Campioni/" // NOTE: Yes, hardcoded for now :(
#define TEST_PATH(s)                      TEST_PREFIX + std::string(s)

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
    ADD_TEST_PATH("PE Test/tn12/scrack.exe", testSCrack);

    ADD_TEST_PATH_NULL("PE Test/CorruptedIT.exe", NULL);
}

void DisassemblerTest::runTests()
{
    REDasm::init();

    std::for_each(this->_tests.begin(), this->_tests.end(), [this](const TestItem& test) {
        QString testpath = QString::fromStdString(test.first);
        QFileInfo fi(testpath);

        if(!fi.exists()) {
            cout << "!!! SKIPPING TEST '" << qUtf8Printable(fi.fileName()) << "', file not found..." << endl << endl;
            return;
        }

        TEST_TITLE(qUtf8Printable(fi.fileName()));
        QByteArray data = this->readFile(testpath);

        if(data.isEmpty()) {
            cout << "!!! File is empty" << endl << endl;
            return;
        }

        this->runTest(data, test.second);
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

QByteArray DisassemblerTest::readFile(const QString &file) const
{
    QFile f(file);

    if(!f.open(QFile::ReadOnly))
        return QByteArray();

    QByteArray ba = f.readAll();
    f.close();
    return ba;
}

void DisassemblerTest::runTest(QByteArray &data, TestCallback testcallback)
{
    FormatPlugin* format = REDasm::getFormat(reinterpret_cast<u8*>(data.data()));
    TEST("Format", format);

    if(!format)
        return;

    ProcessorPlugin* processor = REDasm::getProcessor(format->processor());
    TEST("Processor", processor);

    if(!processor)
        return;

    Buffer buffer(data.data(), data.length());
    Disassembler disassembler(buffer, processor, format);

    cout << "->> Disassembler...";
        disassembler.disassemble();
    cout << TEST_OK << endl;

    if(testcallback)
        testcallback(&disassembler);
}

void DisassemblerTest::testVBEvents(Disassembler *disassembler, const std::map<address_t, string> &vbevents)
{
    SymbolTable* symboltable = disassembler->symbols();
    Symbol* symbol = NULL;

    std::for_each(vbevents.begin(), vbevents.end(), [this, symboltable, &symbol](const std::pair<address_t, std::string>& vbevent) {
        std::string procname = this->replaceAll(vbevent.second, "::", "_");
        symbol = symboltable->symbol(vbevent.first);

        TEST_SYMBOL_NAME("Event " + vbevent.second + " @ " + REDasm::hex(vbevent.first, 0, false),
                         symbol, symbol->is(SymbolTypes::Function), procname);
    });
}

void DisassemblerTest::testCavia(REDasm::Disassembler *disassembler)
{
    SymbolTable* symboltable = disassembler->symbols();

    Symbol* symbol = symboltable->symbol(0x00401000);
    TEST_SYMBOL("EntryPoint", symbol, symbol->isFunction());

    symbol = symboltable->symbol(0x00401029);
    TEST_SYMBOL_NAME("WndProc", symbol, symbol->isFunction(), "DlgProc_401029");
}

void DisassemblerTest::testCM01(Disassembler *disassembler)
{
    SymbolTable* symboltable = disassembler->symbols();

    Symbol* symbol = symboltable->symbol(0x00401128);
    TEST_SYMBOL_NAME("Exported WndProc", symbol, symbol->isFunction() && symbol->is(SymbolTypes::ExportFunction), "WndProc");

    symbol = symboltable->symbol(0x00401253);
    TEST_SYMBOL_NAME("DlgProc @ 00401253", symbol, symbol->isFunction(), "DlgProc_401253");

    symbol = symboltable->symbol(0x0040130A);
    TEST_SYMBOL_NAME("DlgProc @ 0040130A", symbol, symbol->isFunction(), "DlgProc_40130A");

    symbol = symboltable->symbol(0x004020e7);
    TEST_SYMBOL("Ascii String @ 004020E7", symbol, symbol->is(SymbolTypes::String));

    symbol = symboltable->symbol(0x004020f4);
    TEST_SYMBOL("Ascii String @ 004020F4", symbol, symbol->is(SymbolTypes::String));
}

void DisassemblerTest::testSCrack(Disassembler *disassembler)
{
    SymbolTable* symboltable = disassembler->symbols();

    Symbol* symbol = symboltable->symbol(0x004013E4);
    TEST_SYMBOL_NAME("Import VB6 ThunRTMain", symbol, symbol->is(SymbolTypes::Function), "_msvbvm60_dll_ThunRTMain");

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
    SymbolTable* symboltable = disassembler->symbols();

    Symbol* symbol = symboltable->symbol(0x0040110E);
    TEST_SYMBOL_NAME("Import VB5 ThunRTMain", symbol, symbol->is(SymbolTypes::Function), "_msvbvm50_dll_ThunRTMain");

    std::map<address_t, std::string> vbevents;
    vbevents[0x004020C4] = "Form1::Command1::Click";

    this->testVBEvents(disassembler, vbevents);
}
