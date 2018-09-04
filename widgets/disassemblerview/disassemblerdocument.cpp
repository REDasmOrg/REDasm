#include "disassemblerdocument.h"
#include <QJsonDocument>

#define ADDRESS_VARIANT(address) QJsonValue::fromVariant(QVariant::fromValue(address))
#define INDENT_COMMENT 10
#define INDENT_WIDTH 2

DisassemblerDocument::DisassemblerDocument(REDasm::Disassembler *disassembler, QTextDocument* textdocument, QObject *parent): QObject(parent)
{
    this->_disassembler = disassembler;
    this->_symbols = disassembler->symbolTable();
    this->_document = textdocument;
    this->_segment = NULL;
    this->_printer = REDasm::PrinterPtr(disassembler->assembler()->createPrinter(disassembler, disassembler->symbolTable()));

    this->setCurrentPrinter(this->_printer);
    textdocument->setUndoRedoEnabled(false);
}

bool DisassemblerDocument::generate(address_t address, const QTextCursor& cursor)
{
    if(this->isBlockGenerated(address))
        return false;

    this->_textcursor = cursor;
    this->setCurrentPrinter(this->_printer);

    if(!this->_currentprinter)
        return false;

    return true;
}

void DisassemblerDocument::update(address_t address)
{
    REDasm::SymbolPtr symbol = this->_symbols->symbol(address);

    if(!symbol)
        return;

    this->updateInstructions(symbol);
    this->updateSymbol(symbol);

    if(symbol->isFunction())
        this->updateFunction(symbol);
    else if(symbol->is(REDasm::SymbolTypes::Code))
        this->updateLabels(symbol);
}

void DisassemblerDocument::updateInstructions(const REDasm::SymbolPtr& symbol)
{
    REDasm::ReferenceVector refs = this->_disassembler->getReferences(symbol);
    REDasm::InstructionsPool& listing = this->_disassembler->instructions();

    for(auto it = refs.begin(); it != refs.end(); it++)
    {
        if(!this->isBlockGenerated(*it))
            continue;

        REDasm::InstructionPtr instruction = listing[*it];

        if(!this->selectBlock(instruction->address))
            continue;

        this->_textcursor.select(QTextCursor::LineUnderCursor);
        this->appendInstruction(instruction, true);
    }
}

void DisassemblerDocument::updateFunction(const REDasm::SymbolPtr &symbol)
{
    if(!this->isBlockGenerated(symbol->address) || !this->selectBlock(symbol->address))
        return;

    QTextBlock b = this->_textcursor.block();

    if(!b.isValid())
        return;

    if(b.blockFormat().hasProperty(DisassemblerDocument::IsInstructionBlock))
        b = b.previous();

    if(!b.isValid() || !b.blockFormat().hasProperty(DisassemblerDocument::IsFunctionBlock))
        return;

    this->_textcursor.select(QTextCursor::LineUnderCursor);
    this->appendFunctionStart(symbol, true);
}

void DisassemblerDocument::updateLabels(const REDasm::SymbolPtr &symbol)
{
    if(!this->isBlockGenerated(symbol->address))
        return;

    REDasm::InstructionsPool& listing = this->_disassembler->instructions();
    REDasm::ReferenceVector refs = this->_disassembler->getReferences(symbol);

    for(auto rit = refs.begin(); rit != refs.end(); rit++)
    {
        REDasm::InstructionPtr instruction = listing[*rit];

        for(auto it = instruction->targets.begin(); it != instruction->targets.end(); it++)
        {
            if(!this->isBlockGenerated(*it) || !this->selectBlock(*it))
                continue;

            QTextBlock b = this->_textcursor.block();

            if(b.blockFormat().hasProperty(DisassemblerDocument::IsInstructionBlock))
                b = b.previous();

            if(!b.isValid() || !b.blockFormat().hasProperty(DisassemblerDocument::IsLabelBlock))
                continue;

            this->_textcursor.select(QTextCursor::LineUnderCursor);
            this->appendLabel(symbol, true);
        }
    }
}

void DisassemblerDocument::updateSymbol(const REDasm::SymbolPtr &symbol)
{
    if(!this->selectBlock(symbol->address))
        return;

    this->_textcursor.select(QTextCursor::LineUnderCursor);
    this->_pendingsymbols.insert(symbol->address);
    this->appendSymbols(true);
}

void DisassemblerDocument::appendEmpty(address_t address)
{
    this->_textcursor.insertBlock();

    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(address));
    blockformat.setProperty(DisassemblerDocument::IsEmptyBlock, true);
    this->_textcursor.setBlockFormat(blockformat);
}

void DisassemblerDocument::appendLabel(const REDasm::SymbolPtr &symbol, bool replace)
{
    if(!replace)
        this->_textcursor.insertBlock();

    QJsonObject data = { { "action",  DisassemblerDocument::LabelAction },
                         { "address", ADDRESS_VARIANT(symbol->address) } };

    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(symbol->address));
    blockformat.setProperty(DisassemblerDocument::IsLabelBlock, true);
    this->_textcursor.setBlockFormat(blockformat);

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("label_fg"));
    charformat.setAnchor(true);
    charformat.setAnchorHref(DisassemblerDocument::encode(data));
    charformat.setFontUnderline(true);

    this->_textcursor.insertText(QString(" ").repeated(this->getIndent(symbol->address) + INDENT_WIDTH), QTextCharFormat());
    this->_textcursor.insertText(S_TO_QS(symbol->name) + ":", charformat);
}

void DisassemblerDocument::appendFunctionStart(const REDasm::SymbolPtr &symbol, bool replace)
{
    if(!replace)
        this->_textcursor.insertBlock();

    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(symbol->address));
    blockformat.setProperty(DisassemblerDocument::IsFunctionBlock, true);
    this->_textcursor.setBlockFormat(blockformat);

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("header_fg"));

    this->_textcursor.setCharFormat(charformat);
    this->_textcursor.insertText(QString(" ").repeated(this->getIndent(symbol->address)));

    this->_currentprinter->function(symbol, [this, &charformat, symbol](const std::string& pre, const std::string& sym, const std::string& post) {
        if(!pre.empty())
            this->_textcursor.insertText(S_TO_QS(pre));

        QTextCharFormat symcharformat = charformat;
        this->setMetaData(symcharformat, symbol);
        this->_textcursor.setCharFormat(symcharformat);
        this->_textcursor.insertText(S_TO_QS(sym));

        if(!post.empty())
        {
            this->_textcursor.setCharFormat(charformat);
            this->_textcursor.insertText(S_TO_QS(post));
        }
    });

    if(replace)
        return;

    this->_currentprinter->prologue(symbol, [this, symbol](const std::string& line) {
        this->appendInfo(symbol->address, S_TO_QS(line));
    });
}

void DisassemblerDocument::appendInstruction(const REDasm::InstructionPtr &instruction, bool replace)
{
    if(!replace)
    {
        this->_printer->info(instruction, [this, instruction](const std::string& info) {
            this->appendInfo(instruction->address, S_TO_QS(info));
        });

        this->_textcursor.insertBlock();
    }

    this->_generatedblocks.insert(instruction->address);
    this->_pendinginstructions.insert(instruction->address);

    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(instruction->address));
    blockformat.setProperty(DisassemblerDocument::IsInstructionBlock, true);
    this->_textcursor.setBlockFormat(blockformat);

    this->appendAddress(instruction->address);
    this->appendPathInfo(instruction);
    this->appendMnemonic(instruction);
    this->appendOperands(instruction);
    this->appendComment(instruction);
}

void DisassemblerDocument::appendOperands(const REDasm::InstructionPtr &instruction)
{
    this->_currentprinter->out(instruction, [instruction, this](const REDasm::Operand& operand, const std::string& opsize, const std::string& opstr) {
        if(operand.index > 0)
            this->_textcursor.insertText(", ", QTextCharFormat());

        REDasm::SymbolPtr symbol = this->appendOperand(instruction, operand, S_TO_QS(opsize), S_TO_QS(opstr));

        if(!symbol || (this->_generatedblocks.find(symbol->address)) != this->_generatedblocks.end())
            return;

        this->_pendingsymbols.insert(symbol->address);
    });
}

REDasm::SymbolPtr DisassemblerDocument::appendOperand(const REDasm::InstructionPtr& instruction, const REDasm::Operand &operand, const QString& opsize, const QString &opstr)
{
    if(!opsize.isEmpty())
        this->_textcursor.insertText(opsize + " ", QTextCharFormat());

    QTextCharFormat charformat;
    REDasm::SymbolPtr symbol;

    if(operand.isNumeric())
    {
        symbol = this->_symbols->symbol(operand.u_value);

        if(symbol)
        {
            if(symbol->is(REDasm::SymbolTypes::Pointer))
            {
                REDasm::SymbolPtr ptrsymbol = this->_disassembler->dereferenceSymbol(symbol);

                if(ptrsymbol)
                    symbol = ptrsymbol;
            }

            this->setMetaData(charformat, symbol);
        }
        else if(operand.is(REDasm::OperandTypes::Memory))
            charformat.setForeground(THEME_VALUE("memory_fg"));
        else
            charformat.setForeground(THEME_VALUE("immediate_fg"));
    }
    else if(operand.is(REDasm::OperandTypes::Displacement))
        charformat.setForeground(THEME_VALUE("displacement_fg"));
    else if(operand.is(REDasm::OperandTypes::Register))
        charformat.setForeground(THEME_VALUE("register_fg"));

    this->_textcursor.insertText(opstr, charformat);
    return symbol;
}

void DisassemblerDocument::appendAddress(address_t address)
{
    const REDasm::Segment* segment = this->getSegment(address);
    QString segmentname = segment ? S_TO_QS(segment->name) : "unk";

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("address_fg"));

    this->_textcursor.setCharFormat(charformat);
    this->_textcursor.insertText(QString("%1:%2 ").arg(segmentname, HEX_ADDRESS(address)));
    this->_textcursor.insertText(QString(" ").repeated(this->indentWidth()), QTextCharFormat());
}

void DisassemblerDocument::appendPathInfo(const REDasm::InstructionPtr& instruction)
{
    if(instruction->blockIs(REDasm::ListingItemTypes::Ignore))
    {
        this->_textcursor.insertText("  ");
        return;
    }

    if(instruction->blockIs(REDasm::ListingItemTypes::BlockStart))
        this->_textcursor.insertText("/ ");
    else if(instruction->blockIs(REDasm::ListingItemTypes::BlockEnd))
        this->_textcursor.insertText("\\ ");
    else
        this->_textcursor.insertText("| ");
}

void DisassemblerDocument::appendMnemonic(const REDasm::InstructionPtr &instruction)
{
    QTextCharFormat charformat;

    if(instruction->isInvalid())
        charformat.setForeground(THEME_VALUE("instruction_invalid"));
    else if(instruction->is(REDasm::InstructionTypes::Stop))
        charformat.setForeground(THEME_VALUE("instruction_stop"));
    else if(instruction->is(REDasm::InstructionTypes::Nop))
        charformat.setForeground(THEME_VALUE("instruction_nop"));
    else if(instruction->is(REDasm::InstructionTypes::Call))
        charformat.setForeground(THEME_VALUE("instruction_call"));
    else if(instruction->is(REDasm::InstructionTypes::Jump))
    {
        if(instruction->is(REDasm::InstructionTypes::Conditional))
            charformat.setForeground(THEME_VALUE("instruction_jmp_c"));
        else
            charformat.setForeground(THEME_VALUE("instruction_jmp"));
    }

    this->_textcursor.insertText(S_TO_QS(instruction->mnemonic) + " ", charformat);
}

void DisassemblerDocument::appendComment(const REDasm::InstructionPtr &instruction)
{
    if(instruction->comments.empty())
        return;

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("comment_fg"));

    this->_textcursor.insertText(QString(" ").repeated(this->getIndent(instruction->address) + INDENT_COMMENT), QTextCharFormat());
    this->_textcursor.insertText(S_TO_QS(this->_disassembler->comment(instruction)), charformat);
}

void DisassemblerDocument::appendInfo(address_t address, const QString &info)
{
    this->_textcursor.insertBlock();
    this->_textcursor.insertText(QString(" ").repeated(this->getIndent(address)), QTextCharFormat());
    this->_textcursor.insertText(info);
}

void DisassemblerDocument::appendSymbol(const REDasm::SymbolPtr &symbol, const std::string& value, bool replace)
{
    if(!replace)
    {
        if(this->isBlockGenerated(symbol->address))
            return;

        this->moveToBlock(symbol->address);
        this->_textcursor.insertBlock();
    }

    this->_generatedblocks.insert(symbol->address);

    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(symbol->address));
    blockformat.setProperty(DisassemblerDocument::IsSymbolBlock, true);
    this->_textcursor.setBlockFormat(blockformat);
    this->appendAddress(symbol->address);

    QJsonObject data = { { "action", DisassemblerDocument::GotoAction },
                         { "address", ADDRESS_VARIANT(symbol->address) } };

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("label_fg"));
    charformat.setAnchor(true);
    charformat.setAnchorHref(DisassemblerDocument::encode(data));
    this->_textcursor.insertText(S_TO_QS(symbol->name) + " ", charformat);

    if(symbol->is(REDasm::SymbolTypes::String))
        charformat.setForeground(THEME_VALUE("string_fg"));
    else if(!symbol->is(REDasm::SymbolTypes::Pointer))
        charformat.setForeground(THEME_VALUE("data_fg"));

    if(symbol->is(REDasm::SymbolTypes::Pointer))
    {
        REDasm::SymbolPtr ptrsymbol = this->_disassembler->dereferenceSymbol(symbol);

        if(ptrsymbol)
        {
            data["address"] = ADDRESS_VARIANT(ptrsymbol->address);
            charformat.setAnchorHref(DisassemblerDocument::encode(data));
        }
        else
            charformat.setAnchor(false);
    }
    else
        charformat.setAnchor(false);

    this->_textcursor.insertText(S_TO_QS(value), charformat);
}

void DisassemblerDocument::appendSymbols(bool replace)
{
    for(auto it = this->_pendingsymbols.begin(); it != this->_pendingsymbols.end(); it++)
    {
        REDasm::SymbolPtr symbol = this->_symbols->symbol(*it);

        if(!symbol)
            continue;

        this->_currentprinter->symbol(symbol, [this, replace](const REDasm::SymbolPtr& symbol, const std::string& line) {
            this->appendSymbol(symbol, line, replace);
        });
    }

    for(auto it = this->_pendinginstructions.begin(); it != this->_pendinginstructions.end(); it++)
    {
        REDasm::InstructionPtr instruction = this->_disassembler->instructions()[*it];

        this->_currentprinter->symbols(instruction, [this, replace](const REDasm::SymbolPtr& symbol, const std::string& line) {
            this->appendSymbol(symbol, line, replace);
        });
    }

    this->_pendinginstructions.clear();
    this->_pendingsymbols.clear();
}

int DisassemblerDocument::indentWidth() const
{
    return INDENT_WIDTH + 2;
}

int DisassemblerDocument::getIndent(address_t address)
{
    const REDasm::FormatPlugin* format = this->_disassembler->format();
    const REDasm::Segment* segment = this->getSegment(address);

    int width = format->bits() / 4;

    if(segment)
        width += segment->name.length();

    return width + INDENT_WIDTH;
}

const REDasm::Segment *DisassemblerDocument::getSegment(address_t address)
{
    if(this->_segment && this->_segment->contains(address))
        return this->_segment;

    REDasm::FormatPlugin* format = this->_disassembler->format();
    this->_segment = format->segment(address);
    return this->_segment;
}

void DisassemblerDocument::setCurrentPrinter(const REDasm::PrinterPtr &printer)
{
    if(this->_currentprinter == printer)
            return;

    this->_currentprinter = printer;
}

void DisassemblerDocument::setMetaData(QTextCharFormat& charformat, const REDasm::SymbolPtr &symbol)
{
    QJsonObject data = { { "action", DisassemblerDocument::GotoAction },
                         { "address", ADDRESS_VARIANT(symbol->address) } };

    if(symbol->is(REDasm::SymbolTypes::Code))
        charformat.setForeground(THEME_VALUE("header_fg"));
    else if(symbol->is(REDasm::SymbolTypes::String))
        charformat.setForeground(THEME_VALUE("string_fg"));
    else
        charformat.setForeground(THEME_VALUE("data_fg"));

    charformat.setFontUnderline(true);
    charformat.setAnchor(true);
    charformat.setAnchorHref(DisassemblerDocument::encode(data));
}

bool DisassemblerDocument::selectBlock(address_t address)
{
    QTextBlock b = this->_textcursor.block();

    if(!b.blockFormat().hasProperty(DisassemblerDocument::Address))
        b = this->_document->begin();

    address_t currentaddress = b.blockFormat().property(DisassemblerDocument::Address).toULongLong();
    bool searchforward = address > currentaddress;

    for(; b.isValid(); b = searchforward ? b.next() : b.previous())
    {
        QTextBlockFormat blockformat = b.blockFormat();
        address_t blockaddress = blockformat.property(DisassemblerDocument::Address).toULongLong();

        if(blockaddress == address)
            break;
    }

    if(!b.isValid())
        return true;

    this->_textcursor.setPosition(b.position());
    return true;
}

void DisassemblerDocument::moveToBlock(address_t address)
{
    QTextBlock b = this->_document->firstBlock(), lastb;

    while(b.isValid())
    {
        QTextBlockFormat blockformat = b.blockFormat();
        address_t blockaddress = blockformat.property(DisassemblerDocument::Address).toULongLong();

        if(blockaddress > address)
            break;

        lastb = b;
        b = b.next();
    }

    if(lastb.isValid())
    {
        this->_textcursor.setPosition(lastb.position());
        this->_textcursor.movePosition(QTextCursor::EndOfBlock);
    }
    else
        this->_textcursor.movePosition(QTextCursor::End);
}

bool DisassemblerDocument::isBlockGenerated(address_t address)
{
    return this->_generatedblocks.find(address) != this->_generatedblocks.end();
}

QJsonObject DisassemblerDocument::decode(const QString &data)
{
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromBase64(data.toUtf8()));
    return doc.object();
}

QString DisassemblerDocument::encode(const QJsonObject& json)
{
    QJsonDocument doc(json);
    return doc.toJson().toBase64();
}
