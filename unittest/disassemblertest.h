#pragma once

#include <functional>
#include <map>
#include <QStringList>
#include <redasm/disassembler/listing/document/listingdocumentnew.h>
#include <redasm/disassembler/disassembler.h>
#include <redasm/buffer/memorybuffer.h>

class DisassemblerTest
{
    private:
        typedef std::function<void()> TestCallback;
        typedef std::map<REDasm::String, TestCallback> TestList;
        typedef std::pair<REDasm::String, TestCallback> TestItem;

    public:
        DisassemblerTest();
        ~DisassemblerTest();
        void runTests();

    private:
        static std::string replaceAll(std::string str, const std::string& from, const std::string& to);
        void runCurrentTest(const REDasm::String &filepath, const TestCallback& cb);

    private:
        void testTrampolines(const std::map<address_t, REDasm::String> &trampolines);
        void testVBEvents(const std::map<address_t, REDasm::String> &vbevents);

    private: // Tests
        void testCavia();
        void testCM01();
        void testOllyDump();
        void testSCrack();
        void testVB5CrackMe();
        void testIoliARM();
        void testTn11();
        void testHw32Stripped();
        void testJmpTable();
        void testPwrCtlBE();
        void testHelloWorldMFC();
        void testTestRTTI();

    private:
        TestList m_tests;
        std::unique_ptr<REDasm::Disassembler> m_disassembler;
        REDasm::ListingDocumentNew m_document;
        REDasm::MemoryBuffer* m_buffer;
};
