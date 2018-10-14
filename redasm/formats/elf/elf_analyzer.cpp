#include "elf_analyzer.h"

#define LIBC_START_MAIN        "__libc_start_main"
#define LIBC_START_MAIN_ARGC 7

namespace REDasm {

ElfAnalyzer::ElfAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures): Analyzer(disassembler, signatures) { }

void ElfAnalyzer::analyze()
{
    Analyzer::analyze();
    SymbolPtr symbol = m_document->symbol("main");

    if(!symbol)
    {
        AssemblerPlugin* assembler = m_disassembler->assembler();
        SymbolPtr symlibcmain = this->getLibStartMain();

        if(symlibcmain)
        {
            if(ASSEMBLER_IS(assembler, "x86"))
                this->findMain_x86(symlibcmain);
            else
                REDasm::log("WARNING: Unhandled architecture " + REDasm::quoted(assembler->name()));

            symbol = m_document->symbol("main");
        }
    }

    if(symbol)
        m_document->setDocumentEntry(symbol->address);
    else
        REDasm::log("WARNING: Cannot find 'main' symbol");
}

void ElfAnalyzer::findMain_x86(const SymbolPtr& symlibcmain)
{
    ReferenceVector refs = m_disassembler->getReferences(symlibcmain->address);

    if(refs.size() > 1)
        REDasm::log(REDasm::quoted(LIBC_START_MAIN) + " contains " + std::to_string(refs.size()) + " reference(s)");

    auto it = m_document->instructionItem(refs.front());

    if(it == m_document->end())
        return;

    if(ASSEMBLER_IS(m_disassembler->assembler(), "x86_64"))
        this->findMain_x86_64(it);
    else
        this->findMain_x86(it);

    this->disassembleLibStartMain();
}

void ElfAnalyzer::findMain_x86(ListingDocument::iterator it)
{
    for(int i = 0; i < LIBC_START_MAIN_ARGC; it--)
    {
        if((*it)->is(ListingItem::InstructionItem))
        {
            InstructionPtr instruction = m_document->instruction((*it)->address);

            if(instruction->is(InstructionTypes::Push))
            {
                const Operand& op = instruction->op(0);

                if(op.isNumeric())
                {
                    if(i == 0)
                        m_libcmain["main"] = op.u_value;
                    else if(i == 3)
                        m_libcmain["init"] = op.u_value;
                    else if(i == 4)
                    {
                        m_libcmain["fini"] = op.u_value;
                        break;
                    }
                }

                i++;
            }
        }

        if(it == m_document->begin())
            break;
    }
}

void ElfAnalyzer::findMain_x86_64(ListingDocument::iterator it)
{
    do
    {
        it--;

        if((*it)->is(ListingItem::InstructionItem))
        {
            InstructionPtr instruction = m_document->instruction((*it)->address);

            if(instruction->is(InstructionTypes::Load))
            {
                const Operand op1 = instruction->op(0);
                const Operand op2 = instruction->op(1);

                if(!op1.is(OperandTypes::Register) || !op2.isNumeric())
                    continue;

                if(op1.reg.r == X86_REG_RDI)
                    m_libcmain["main"] = op2.u_value;
                else if(op1.reg.r == X86_REG_RCX)
                    m_libcmain["init"] = op2.u_value;
                else if(op1.reg.r == X86_REG_R8)
                {
                    m_libcmain["fini"] = op2.u_value;
                    break;
                }
            }
        }
    }
    while(it != m_document->begin());
}

void ElfAnalyzer::disassembleLibStartMain()
{
    for(auto& it : m_libcmain)
    {
        m_document->lock(it.second, it.first, SymbolTypes::Function);
        m_disassembler->disassemble(it.second);
    }

    m_libcmain.clear();
}

SymbolPtr ElfAnalyzer::getLibStartMain()
{
    SymbolPtr symlibcmain = m_document->symbol(REDasm::trampoline(LIBC_START_MAIN));

    if(!symlibcmain)
        symlibcmain = m_document->symbol(LIBC_START_MAIN);

    return symlibcmain;
}

} // namespace REDasm
