#ifndef DISASSEMBLERTEST_H
#define DISASSEMBLERTEST_H

#include <map>
#include <functional>
#include <QStringList>
#include "redasm/disassembler/disassembler.h"

class DisassemblerTest
{
    private:
        typedef std::function<void(REDasm::Disassembler*)> TestCallback;
        typedef std::map<std::string, TestCallback> TestList;
        typedef std::pair<std::string, TestCallback> TestItem;

    public:
        DisassemblerTest();
        void runTests();

    private:
        static std::string replaceAll(std::string str, const std::string& from, const std::string& to);
        static QByteArray readFile(const QString& file);
        static void runTest(QByteArray &data, const TestCallback &testcallback);

    private:
        void testVBEvents(REDasm::Disassembler* disassembler, const std::map<address_t, std::string>& vbevents);

    private: // Tests
        void testCavia(REDasm::Disassembler* disassembler);
        void testCM01(REDasm::Disassembler* disassembler);
        void testOllyDump(REDasm::Disassembler* disassembler);
        void testSCrack(REDasm::Disassembler* disassembler);
        void testVB5CrackMe(REDasm::Disassembler* disassembler);
        void testIoliARM(REDasm::Disassembler* disassembler);
        void testJumpTables(REDasm::Disassembler* disassembler);

    private:
        TestList _tests;
};

#endif // DISASSEMBLERTEST_H
