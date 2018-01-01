#include "disassemblerdocument.h"
#include <QJsonDocument>
#include <QVariant>
#include <QFile>

#define THEME_VALUE(name)        (this->_theme.contains(name) ? QColor(this->_theme[name].toString()) : QColor())
#define ADDRESS_VARIANT(address) QJsonValue::fromVariant(QVariant::fromValue(address))
#define INDENT_COMMENT 10
#define INDENT_WIDTH 2

DisassemblerDocument::DisassemblerDocument(REDasm::Disassembler *disassembler, const QString& theme, QTextDocument* textdocument, QObject *parent): QObject(parent)
{
    this->_disassembler = disassembler;
    this->_symbols = disassembler->symbolTable();
    this->_document = textdocument;
    this->_segment = NULL;
    this->_printer = REDasm::PrinterPtr(disassembler->processor()->createPrinter(disassembler, disassembler->symbolTable()));

    this->setCurrentPrinter(this->_printer);
    this->setTheme(theme);
    textdocument->setUndoRedoEnabled(false);
}

QColor DisassemblerDocument::highlightColor() const
{
    return QColor(THEME_VALUE("highlight"));
}

QColor DisassemblerDocument::seekColor() const
{
    return QColor(THEME_VALUE("seek"));
}

QColor DisassemblerDocument::dottedColor() const
{
    return QColor(THEME_VALUE("dotted_fg"));
}

void DisassemblerDocument::setTheme(const QString &theme)
{
    QFile f(QString(":/themes/disassembler/%1.json").arg(theme));

    if(!f.open(QFile::ReadOnly))
    {
        qWarning("Cannot load '%s' theme", qUtf8Printable(theme));
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());

    if(doc.isObject())
        this->_theme = doc.object();

    f.close();
}

bool DisassemblerDocument::generate(address_t address, const QTextCursor& cursor)
{
    if(this->isInstructionGenerated(address))
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

    if(symbol->isFunction())
        this->updateFunction(symbol);
    else if(symbol->is(REDasm::SymbolTypes::Code))
        this->updateLabels(symbol);
}

void DisassemblerDocument::updateInstructions(const REDasm::SymbolPtr& symbol)
{
    REDasm::ReferenceVector refs = this->_disassembler->getReferences(symbol);
    REDasm::Listing& listing = this->_disassembler->listing();

    for(auto it = refs.begin(); it != refs.end(); it++)
    {
        if(!this->isInstructionGenerated(*it))
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
    if(!this->isInstructionGenerated(symbol->address) || !this->selectBlock(symbol->address))
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
    if(!this->isInstructionGenerated(symbol->address))
        return;

    REDasm::Listing& listing = this->_disassembler->listing();
    REDasm::ReferenceVector refs = this->_disassembler->getReferences(symbol);

    for(auto rit = refs.begin(); rit != refs.end(); rit++)
    {
        REDasm::InstructionPtr instruction = listing[*rit];

        for(auto it = instruction->targets.begin(); it != instruction->targets.end(); it++)
        {
            if(!this->isInstructionGenerated(*it) || !this->selectBlock(*it))
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

void DisassemblerDocument::appendFunctionEnd(const REDasm::InstructionPtr &lastinstruction)
{
    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(lastinstruction->address));
    blockformat.setProperty(DisassemblerDocument::IsEmptyBlock, true);
    this->_textcursor.setBlockFormat(blockformat);
    this->_textcursor.insertBlock();
}

void DisassemblerDocument::appendLabel(const REDasm::SymbolPtr &symbol, bool replace)
{
    REDasm::ReferenceVector refs = this->_disassembler->getReferences(symbol);

    QJsonObject data = { { "action",  refs.size() > 1 ? DisassemblerDocument::XRefAction : DisassemblerDocument::GotoAction },
                         { "address", ADDRESS_VARIANT(refs.size() > 1 ? symbol->address : refs.front()) } };

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

    if(!replace)
        this->_textcursor.insertBlock();
}

void DisassemblerDocument::appendFunctionStart(const REDasm::SymbolPtr &symbol, bool replace)
{
    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(symbol->address));
    blockformat.setProperty(DisassemblerDocument::IsFunctionBlock, true);
    this->_textcursor.setBlockFormat(blockformat);

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("header_fg"));

    this->_textcursor.setCharFormat(charformat);
    this->_textcursor.insertText(QString(" ").repeated(this->getIndent(symbol->address)));

    this->_currentprinter->header(symbol, [this, &charformat, symbol](const std::string& pre, const std::string& sym, const std::string& post) {
        if(!pre.empty())
            this->_textcursor.insertText(S_TO_QS(pre));

        QTextCharFormat symcharformat = charformat;
        this->setMetaData(symcharformat, symbol, true);
        this->_textcursor.setCharFormat(symcharformat);
        this->_textcursor.insertText(S_TO_QS(sym));

        if(!post.empty())
        {
            this->_textcursor.setCharFormat(charformat);
            this->_textcursor.insertText(S_TO_QS(post));
        }
    });

    if(!replace)
    {
        charformat.setForeground(THEME_VALUE("prologue_fg"));
        this->_textcursor.setCharFormat(charformat);

        this->_currentprinter->prologue(symbol, [this, symbol](const std::string& line) {
            this->_textcursor.insertBlock();
            this->_textcursor.insertText(QString(" ").repeated(this->getIndent(symbol->address)));
            this->_textcursor.insertText(S_TO_QS(line));
        });

        this->_textcursor.insertBlock();
    }
}

void DisassemblerDocument::appendInstruction(const REDasm::InstructionPtr &instruction, bool replace)
{
    this->_generatedinstructions.insert(instruction->address);

    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(instruction->address));
    blockformat.setProperty(DisassemblerDocument::IsInstructionBlock, true);
    this->_textcursor.setBlockFormat(blockformat);

    this->appendAddress(instruction);
    this->_textcursor.insertText(QString(" ").repeated(this->indentWidth()), QTextCharFormat());
    this->appendPathInfo(instruction);
    this->appendMnemonic(instruction);
    this->appendOperands(instruction);
    this->appendComment(instruction);

    if(!replace)
        this->_textcursor.insertBlock();
}

void DisassemblerDocument::appendOperands(const REDasm::InstructionPtr &instruction)
{
    this->_currentprinter->out(instruction, [this](const REDasm::Operand& operand, const std::string& opsize, const std::string& opstr) {
        if(operand.index > 0)
            this->_textcursor.insertText(", ", QTextCharFormat());

        this->appendOperand(operand, S_TO_QS(opsize), S_TO_QS(opstr));
    });
}

void DisassemblerDocument::appendOperand(const REDasm::Operand &operand, const QString& opsize, const QString &opstr)
{
    if(!opsize.isEmpty())
        this->_textcursor.insertText(opsize + " ", QTextCharFormat());

    QTextCharFormat charformat;

    if(operand.is(REDasm::OperandTypes::Immediate) || operand.is(REDasm::OperandTypes::Memory))
    {
        REDasm::SymbolPtr symbol = this->_symbols->symbol(operand.is(REDasm::OperandTypes::Immediate) ? operand.s_value :
                                                                                                        operand.u_value);

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
        else
            charformat.setForeground(operand.is(REDasm::OperandTypes::Immediate) ? THEME_VALUE("immediate_fg") :
                                                                                   THEME_VALUE("memory_fg"));
    }
    else if(operand.is(REDasm::OperandTypes::Displacement))
    {
        REDasm::SymbolPtr symbol = this->_symbols->symbol(operand.mem.displacement);

        if(symbol)
            this->setMetaData(charformat, symbol, !operand.mem.displacementOnly());
        else
            charformat.setForeground(THEME_VALUE("displacement_fg"));
    }
    else if(operand.is(REDasm::OperandTypes::Register))
        charformat.setForeground(THEME_VALUE("register_fg"));

    this->_textcursor.insertText(opstr, charformat);
}

void DisassemblerDocument::appendAddress(const REDasm::InstructionPtr &instruction)
{
    const REDasm::Segment* segment = this->getSegment(instruction->address);
    QString address = segment ? S_TO_QS(segment->name) : "unk";

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("address_fg"));

    this->_textcursor.setCharFormat(charformat);
    this->_textcursor.insertText(QString("%1:%2 ").arg(address, HEX_ADDRESS(instruction->address)));
}

void DisassemblerDocument::appendPathInfo(const REDasm::InstructionPtr& instruction)
{
    if(instruction->blockIs(REDasm::BlockTypes::Ignore))
    {
        this->_textcursor.insertText("  ");
        return;
    }

    if(instruction->blockIs(REDasm::BlockTypes::BlockStart))
        this->_textcursor.insertText("/ ");
    else if(instruction->blockIs(REDasm::BlockTypes::BlockEnd))
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

void DisassemblerDocument::setMetaData(QTextCharFormat& charformat, const REDasm::SymbolPtr &symbol, bool showxrefs)
{
    QJsonObject data = { { "action",  DisassemblerDocument::XRefAction },
                         { "address", ADDRESS_VARIANT(symbol->address) } };

    if(symbol->is(REDasm::SymbolTypes::Code))
    {
        if(!showxrefs)
            data["action"] = DisassemblerDocument::GotoAction;

        charformat.setForeground(THEME_VALUE("header_fg"));
    }
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
        return false;

    this->_textcursor.setPosition(b.position());
    return true;
}

bool DisassemblerDocument::isInstructionGenerated(address_t address)
{
    return this->_generatedinstructions.find(address) != this->_generatedinstructions.end();
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
