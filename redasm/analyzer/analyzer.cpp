#include "analyzer.h"
#include "../support/hash.h"

namespace REDasm {

Analyzer::Analyzer(DisassemblerAPI *disassembler, const SignatureFiles &signaturefiles): _disassembler(disassembler), _signaturefiles(signaturefiles)
{

}

Analyzer::~Analyzer()
{

}

void Analyzer::analyze(Listing &listing)
{
    this->loadSignatures(listing);

    listing.symbolTable()->iterate(SymbolTypes::FunctionMask, [this, &listing](SymbolPtr symbol) -> bool {
        this->findTrampolines(listing, symbol);
        return true;
    });
}

bool Analyzer::checkCrc16(const SymbolPtr& symbol, const Signature& signature, const SignatureDB& signaturedb)
{
    if(signaturedb.signatureType() != SignatureDB::IDASignature)
        return true;

    Buffer buffer;

    if(!this->_disassembler->getBuffer(symbol->address + signature.length(), buffer))
        return false;

    if(buffer.length < signature.alen)
        return false;

    if(Hash::crc16(buffer.data, signature.alen) == signature.asum)
        return true;

    return false;
}

void Analyzer::loadSignatures(Listing& listing)
{
    std::for_each(this->_signaturefiles.begin(), this->_signaturefiles.end(), [this, &listing](const std::string& signaturefile) {
        SignatureDB sigdb;

        if(sigdb.readPath(signaturefile))
            this->findSignatures(sigdb, listing);
    });
}

void Analyzer::findSignatures(SignatureDB &signaturedb, Listing& listing)
{
    listing.symbolTable()->iterate(SymbolTypes::FunctionMask, [this, &signaturedb, &listing](SymbolPtr symbol) -> bool {
        Signature signature;
        std::string pattern = this->_disassembler->readHex(symbol->address, signaturedb.longestPattern());

        if(signaturedb.match(pattern, signature) && this->checkCrc16(symbol, signature, signaturedb)) {
            symbol->lock();
            listing.symbolTable()->update(symbol, signature.name);
        }

        return true;
    });
}

void Analyzer::findTrampolines(Listing &listing, SymbolPtr symbol)
{
    if(symbol->is(SymbolTypes::Locked))
        return;

    SymbolTable* symboltable = listing.symbolTable();
    Listing::iterator it = listing.find(symbol->address);

    if(it == listing.end())
        return;

    const AssemblerPlugin* assembler = listing.assembler();
    SymbolPtr symimport;

    if(ASSEMBLER_IS(assembler, "x86"))
        symimport = this->findTrampolines_x86(it, symboltable);
    else if(ASSEMBLER_IS(assembler, "ARM"))
        symimport = this->findTrampolines_arm(it, symboltable);

    if(!symimport || !symimport->is(SymbolTypes::Import))
        return;

    symbol->type |= SymbolTypes::Locked;
    symboltable->update(symbol, "_" + REDasm::normalize(symimport->name));
    this->_disassembler->pushReference(symimport, *it);
}

SymbolPtr Analyzer::findTrampolines_x86(Listing::iterator& it, SymbolTable* symboltable)
{
    const InstructionPtr& instruction = *it;

    if(!instruction->is(InstructionTypes::Jump))
        return NULL;

    if(!instruction->hasTargets())
        return NULL;

    return symboltable->symbol(instruction->target());
}

SymbolPtr Analyzer::findTrampolines_arm(Listing::iterator& it, SymbolTable *symboltable)
{
    const InstructionPtr& instruction1 = *it;
    const InstructionPtr& instruction2 = *(++it);

    if(instruction1->isInvalid() || instruction2->isInvalid())
        return NULL;

    if((instruction1->mnemonic != "ldr") && (instruction2->mnemonic != "ldr"))
        return NULL;

    if(!instruction1->operands[1].is(OperandTypes::Memory) && (instruction2->operands[0].reg.r != ARM_REG_PC))
        return NULL;

    u64 target = instruction1->operands[1].u_value, importaddress = 0;

    if(!this->_disassembler->readAddress(target, sizeof(u32), importaddress))
        return NULL;

    SymbolPtr symbol = symboltable->symbol(target), impsymbol = symboltable->symbol(importaddress);

    if(symbol && impsymbol)
        symboltable->update(symbol, "imp." + impsymbol->name);

    return impsymbol;
}

} // namespace REDasm
