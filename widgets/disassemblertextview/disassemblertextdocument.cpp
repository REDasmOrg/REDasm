#include "disassemblertextdocument.h"

DisassemblerTextDocument::DisassemblerTextDocument(REDasm::Disassembler *disassembler, const QString &theme, QTextDocument *document, QObject *parent): DisassemblerDocument(disassembler, theme, document, parent), _isvmil(false)
{
}

bool DisassemblerTextDocument::generate(address_t address, const QTextCursor &cursor)
{
    if(!DisassemblerDocument::generate(address, cursor))
        return false;

    REDasm::SymbolTable* symboltable = this->_disassembler->symbolTable();

    this->moveToBlock(address);
    this->_textcursor.beginEditBlock();

    REDasm::SymbolPtr symbol = symboltable->symbol(address);

    if(!symbol)
        return false;

    if(symbol->isFunction())
    {
        REDasm::Listing& listing = this->_disassembler->listing();

        listing.iterateFunction(address, [this](const REDasm::InstructionPtr& i) { this->appendInstruction(i); },
                                         [this](const REDasm::SymbolPtr& s) { this->appendFunctionStart(s); },
                                         [this](const REDasm::InstructionPtr& i) { this->appendEmpty(i->address); },
                                         [this](const REDasm::SymbolPtr& s) { this->appendLabel(s); });

    }
    else
        this->_pendingsymbols.insert(address);

    this->appendSymbols();
    this->_textcursor.endEditBlock();
    return true;
}

bool DisassemblerTextDocument::generateVMIL(address_t address, const QTextCursor &cursor)
{
    this->_isvmil = true;
    this->_textcursor = cursor;

    if(!this->_vmilprinter)
    {
        this->_vmilprinter = std::make_shared<REDasm::VMIL::VMILPrinter>(this->_printer, this->_disassembler, this->_disassembler->symbolTable());
        this->setCurrentPrinter(this->_vmilprinter);
    }

    this->_textcursor.beginEditBlock();

    this->_disassembler->iterateVMIL(address, [this](const REDasm::InstructionPtr& i) { this->appendInstruction(i); },
                                              [this](const REDasm::SymbolPtr& s) { this->appendFunctionStart(s); },
                                              [this](const REDasm::InstructionPtr& i) { this->appendEmpty(i->address); },
                                              [this](const REDasm::SymbolPtr& s) { this->appendLabel(s); });

    this->_textcursor.endEditBlock();
    this->_isvmil = false;
    return true;
}
