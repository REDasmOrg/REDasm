#include "disassemblertest.h"
#include "redasm/disassembler/disassembler.h"
#include <QApplication>
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

#define ADD_TEST(t, cb)                  m_tests[t] = std::bind(&DisassemblerTest::cb, this)
#define ADD_TEST_NULL(t, cb)             m_tests[t] = NULL;
#define ADD_TEST_PATH(t, cb)             m_tests[TEST_PATH(t)] = std::bind(&DisassemblerTest::cb, this)
#define ADD_TEST_PATH_NULL(t, cb)        m_tests[TEST_PATH(t)] = NULL;

using namespace std;
using namespace REDasm;

DisassemblerTest::DisassemblerTest(): m_document(NULL)
{
    ADD_TEST("/home/davide/Programmazione/Cavia.exe", testCavia);

    ADD_TEST_PATH("PE Test/CM01.exe", testCM01);
    ADD_TEST_PATH("PE Test/VB5CRKME.EXE", testVB5CrackMe);
    ADD_TEST_PATH("PE Test/OllyDump.dll", testOllyDump);
    ADD_TEST_PATH("PE Test/tn_11.exe", testTn11);
    ADD_TEST_PATH("IOLI-crackme/bin-pocketPC/crackme0x01.arm.exe", testIoliARM);
    ADD_TEST_PATH("PE Test/tn12/scrack.exe", testSCrack);

    ADD_TEST_PATH_NULL("PE Test/CorruptedIT.exe", NULL);

    REDasm::setLoggerCallback([](const std::string&) { });
    REDasm::init(QDir::currentPath().toStdString());
}

void DisassemblerTest::runTests()
{
    for(const TestItem& test : m_tests)
    {
        QString testpath = QString::fromStdString(test.first);
        QFileInfo fi(testpath);

        if(!fi.exists())
        {
            cout << "!!! SKIPPING TEST '" << qUtf8Printable(fi.fileName()) << "', file not found..." << endl << endl;
            return;
        }

        TEST_TITLE(qUtf8Printable(fi.fileName()));
        m_data = DisassemblerTest::readFile(testpath);

        if(m_data.isEmpty())
        {
            cout << "!!! File is empty" << endl << endl;
            return;
        }

        this->runCurrentTest(test.second);
        cout << REPEATED('-') << REPEATED('-') << REPEATED('-') << endl << endl;
    }
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

void DisassemblerTest::runCurrentTest(const TestCallback &cb)
{
    Buffer buffer(m_data.data(), m_data.length());
    FormatPlugin* format = REDasm::getFormat(buffer);
    TEST("Format", format);

    if(!format)
        return;

    AssemblerPlugin* assembler = REDasm::getAssembler(format->assembler());
    TEST("Assembler", assembler);

    if(!assembler)
        return;

    m_disassembler = std::make_unique<Disassembler>(assembler, format);
    m_document = m_disassembler->document();

    cout << "->> Disassembler...";
    m_disassembler->disassemble();
    cout << TEST_OK << endl;

    if(cb)
        cb();
}

void DisassemblerTest::testVBEvents(const std::map<address_t, string> &vbevents)
{
    std::for_each(vbevents.begin(), vbevents.end(), [&](const std::pair<address_t, std::string>& vbevent) {
        std::string procname = DisassemblerTest::replaceAll(vbevent.second, "::", "_");
        SymbolPtr symbol = m_document->symbol(vbevent.first);

        TEST_SYMBOL_NAME("Event " + vbevent.second + " @ " + REDasm::hex(vbevent.first, 0, false),
                         symbol, symbol->isFunction(), procname);
    });
}

void DisassemblerTest::testCavia()
{
    SymbolPtr symbol = m_document->symbol(0x00401000);
    TEST_SYMBOL("EntryPoint", symbol, symbol->isFunction());

    symbol = m_document->symbol(0x00401029);
    TEST_SYMBOL_NAME("WndProc", symbol, symbol->isFunction(), "DlgProc_401029");
}

void DisassemblerTest::testCM01()
{
    SymbolPtr symbol = m_document->symbol(0x00401128);
    TEST_SYMBOL_NAME("Exported WndProc", symbol, symbol->isFunction() && symbol->is(SymbolTypes::ExportFunction), "WndProc");

    symbol = m_document->symbol(0x00401253);
    TEST_SYMBOL_NAME("DlgProc @ 00401253", symbol, symbol->isFunction(), "DlgProc_401253");

    symbol = m_document->symbol(0x0040130A);
    TEST_SYMBOL_NAME("DlgProc @ 0040130A", symbol, symbol->isFunction(), "DlgProc_40130A");

    symbol = m_document->symbol(0x004020E7);
    TEST_SYMBOL("Ascii String @ 004020E7", symbol, symbol->is(SymbolTypes::String));

    symbol = m_document->symbol(0x00402129);
    TEST_SYMBOL("Ascii String @ 00402129", symbol, symbol->is(SymbolTypes::String));

    symbol = m_document->symbol(0x00402134);
    TEST_SYMBOL("Ascii String @ 00402134", symbol, symbol->is(SymbolTypes::String));
}

void DisassemblerTest::testOllyDump()
{
    SymbolPtr symbol = m_document->symbol(0x00403BDC);
    TEST_SYMBOL("Checking Function @ 00403bdc", symbol, symbol->isFunction());

    InstructionPtr instruction = m_document->instruction(0x00403BEA);
    TEST("Checking CALL @ 0x00403BEA", instruction);

    if(!instruction)
        return;

    TEST("Validating CALL @ 0x00403BEA target", instruction->is(InstructionTypes::Call) && instruction->hasTargets());

    symbol = m_document->symbol(0x00407730);
    TEST_SYMBOL("Checking if target an address table", symbol, symbol->isTable());

    if(!symbol)
        return;

    symbol = m_disassembler->dereferenceSymbol(symbol);
    TEST_SYMBOL("Checking if dereferenced pointer is a function", symbol, symbol->isFunction());
}

void DisassemblerTest::testSCrack()
{
    SymbolPtr symbol = m_document->symbol(0x004013E4);
    TEST_SYMBOL_NAME("Import VB6 ThunRTMain", symbol, symbol->isFunction(), "_msvbvm60_dll_ThunRTMain");

    symbol = m_document->symbol(0x00402B1C);
    TEST_SYMBOL("Wide String @ 0x00402b1c", symbol, symbol->is(SymbolTypes::WideString));

    symbol = m_document->symbol(0x00402B2C);
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

    this->testVBEvents(vbevents);
}

void DisassemblerTest::testVB5CrackMe()
{
    SymbolPtr symbol = m_document->symbol(0x0040110E);
    TEST_SYMBOL_NAME("Import VB5 ThunRTMain", symbol, symbol->is(SymbolTypes::Function), "_msvbvm50_dll_ThunRTMain");

    symbol = m_document->symbol(0x00401EB8);
    TEST_SYMBOL("Wide String @ 0x00401EB8", symbol, symbol->is(SymbolTypes::WideString));

    symbol = m_document->symbol(0x00401EF8);
    TEST_SYMBOL("Wide String @ 0x00401EF8", symbol, symbol->is(SymbolTypes::WideString));

    symbol = m_document->symbol(0x00401F08);
    TEST_SYMBOL("Wide String @ 0x00401F08", symbol, symbol->is(SymbolTypes::WideString));

    symbol = m_document->symbol(0x00401F44);
    TEST_SYMBOL("Wide String @ 0x00401F44", symbol, symbol->is(SymbolTypes::WideString));

    std::map<address_t, std::string> vbevents;
    vbevents[0x004020C4] = "Form1::Command1::Click";

    this->testVBEvents(vbevents);
}

void DisassemblerTest::testIoliARM()
{
    InstructionPtr instruction = m_document->instruction(0x00011064);
    TEST("Checking LDR @ 0x00011064", instruction);

    if(!instruction)
        return;

    TEST("Checking LDR's operands count", (instruction->mnemonic == "ldr") && (instruction->operands.size() >= 2));

    Operand op = instruction->operands[1];
    TEST("Checking LDR's operand 2", op.is(OperandTypes::Memory));

    SymbolPtr symbol = m_document->symbol(op.u_value);
    TEST_SYMBOL("Checking LDR's operand 2 symbol", symbol, symbol->is(SymbolTypes::Data) && symbol->is(SymbolTypes::Pointer));

    symbol = m_disassembler->dereferenceSymbol(symbol);
    TEST_SYMBOL("Checking LDR's operand 2 dereferenced string", symbol, symbol->is(SymbolTypes::String));

    instruction = m_document->instruction(0x00011088);
    TEST("Checking LDR @ 0x00011088", instruction);

    if(!instruction)
        return;

    TEST("Checking LDR's operands count", (instruction->mnemonic == "ldr") && (instruction->operands.size() >= 2));

    op = instruction->operands[1];
    TEST("Checking LDR's operand 2", op.is(OperandTypes::Memory));

    u64 value = 0;
    symbol = m_document->symbol(op.u_value);
    TEST_SYMBOL("Checking LDR's operand 2 symbol", symbol, symbol->is(SymbolTypes::Data) && symbol->is(SymbolTypes::Pointer));
    TEST("Checking dereferenced value", m_disassembler->dereference(symbol->address, &value) && (value == 0x149a));
}

void DisassemblerTest::testTn11()
{
    InstructionPtr instruction = m_document->instruction(0x004010C0);
    TEST("Checking DlgProc @ 0x00401197", instruction);

    instruction = m_document->instruction(0x00401197);
    TEST("Checking JUMP TABLE @ 0x00401197", instruction);

    if(!instruction)
        return;

    TEST("Checking TARGETS count @ 0x00401197", instruction->targets.size() == 5);

    if(instruction->targets.size() != 5)
        return;

    size_t i = 0;

    for(address_t target : instruction->targets)
    {
        SymbolPtr symbol = m_document->symbol(target);
        instruction = m_document->instruction(target);

        TEST("Checking CASE #" + std::to_string(i) + " @ " + REDasm::hex(target), symbol && symbol->is(SymbolTypes::Code) && instruction);
        i++;
    }
}
