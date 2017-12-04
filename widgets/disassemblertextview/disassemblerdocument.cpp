#include "disassemblerdocument.h"
#include <QJsonDocument>
#include <QTextBlock>
#include <QVariant>
#include <QFile>

#define THEME_VALUE(name)        (this->_theme.contains(name) ? QColor(this->_theme[name].toString()) : QColor())
#define ADDRESS_VARIANT(address) QJsonValue::fromVariant(QVariant::fromValue(address))
#define INDENT_COMMENT 10
#define INDENT_WIDTH 2

DisassemblerDocument::DisassemblerDocument(REDasm::Disassembler *disassembler, const QString& theme, QTextDocument* textdocument, const QTextCursor& textcursor, QObject *parent): QObject(parent)
{
    this->_disassembler = disassembler;
    this->_symbols = disassembler->symbolTable();
    this->_document = textdocument;
    this->_textcursor = textcursor;
    this->_segment = NULL;

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

void DisassemblerDocument::generate(address_t address, const QTextCursor& cursor)
{
    if(this->isGenerated(address))
        return;

    this->_textcursor = cursor;

    this->selectBlock(address);
    this->_textcursor.beginEditBlock();

    REDasm::Listing& listing = this->_disassembler->listing();

    listing.iterateFunction(address, [this](const REDasm::InstructionPtr& i) { this->appendInstruction(i); },
                                     [this](const REDasm::SymbolPtr& s) { this->appendFunctionStart(s); },
                                     [this](const REDasm::InstructionPtr& i) { this->appendFunctionEnd(i); },
                                     [this](const REDasm::SymbolPtr& s) { this->appendLabel(s); });

    this->_textcursor.endEditBlock();
}

void DisassemblerDocument::appendFunctionEnd(const REDasm::InstructionPtr &lastinstruction)
{
    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(lastinstruction->address));
    blockformat.setProperty(DisassemblerDocument::IsEmptyBlock, true);
    this->_textcursor.setBlockFormat(blockformat);
    this->_textcursor.insertBlock();
}

void DisassemblerDocument::appendLabel(const REDasm::SymbolPtr &symbol)
{
    REDasm::ReferenceVector refs = this->_disassembler->getReferences(symbol);

    QJsonObject data = { { "action", refs.size() > 1 ? DisassemblerDocument::XRefAction : DisassemblerDocument::GotoAction },
                         { "address", ADDRESS_VARIANT(refs.size() > 1 ? symbol->address : refs.front()) } };

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("label_fg"));

    charformat.setAnchor(true);
    charformat.setAnchorHref(DisassemblerDocument::encode(data));
    charformat.setFontUnderline(true);

    this->_textcursor.insertText(QString(" ").repeated(this->getIndent(symbol->address) + INDENT_WIDTH), QTextCharFormat());
    this->_textcursor.insertText(S_TO_QS(symbol->name) + ":", charformat);
    this->_textcursor.insertBlock();
}

void DisassemblerDocument::appendFunctionStart(const REDasm::SymbolPtr &symbol)
{
    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(symbol->address));
    blockformat.setProperty(DisassemblerDocument::IsFunctionBlock, true);
    this->_textcursor.setBlockFormat(blockformat);

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("function_fg"));

    this->_textcursor.setCharFormat(charformat);
    this->_textcursor.insertText(QString(" ").repeated(this->getIndent(symbol->address)));
    this->_textcursor.insertText(QString("=").repeated(20));
    this->_textcursor.insertText(" FUNCTION ");

    QTextCharFormat symcharformat = charformat;
    this->setMetaData(symcharformat, symbol, true);
    this->_textcursor.setCharFormat(symcharformat);
    this->_textcursor.insertText(S_TO_QS(symbol->name));

    this->_textcursor.setCharFormat(charformat);
    this->_textcursor.insertText(" ");
    this->_textcursor.insertText(QString("=").repeated(20));
    this->_textcursor.insertBlock();
}

void DisassemblerDocument::appendInstruction(const REDasm::InstructionPtr &instruction)
{
    this->_generated.insert(instruction->address);

    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(instruction->address));
    blockformat.setProperty(DisassemblerDocument::IsInstructionBlock, true);
    this->_textcursor.setBlockFormat(blockformat);


    this->appendAddress(instruction);
    this->appendMnemonic(instruction);

    this->_disassembler->out(instruction, [this](const REDasm::Operand& operand, const std::string& opstr) {
        if(operand.index > 0)
            this->_textcursor.insertText(", ", QTextCharFormat());

        this->appendOperand(operand, S_TO_QS(opstr));
    });

    this->appendComment(instruction);
    this->_textcursor.insertBlock();
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

    this->_textcursor.insertText(QString(" ").repeated(INDENT_WIDTH + 2), QTextCharFormat());
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

void DisassemblerDocument::appendOperand(const REDasm::Operand &operand, const QString &opstr)
{
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

void DisassemblerDocument::setMetaData(QTextCharFormat& charformat, const REDasm::SymbolPtr &symbol, bool showxrefs)
{
    QJsonObject data = { { "action",  DisassemblerDocument::XRefAction },
                         { "address", ADDRESS_VARIANT(symbol->address) } };

    if(symbol->is(REDasm::SymbolTypes::Code))
    {
        if(!showxrefs)
            data["action"] = DisassemblerDocument::GotoAction;

        charformat.setForeground(THEME_VALUE("function_fg"));
    }
    else if(symbol->is(REDasm::SymbolTypes::String))
        charformat.setForeground(THEME_VALUE("string_fg"));
    else
        charformat.setForeground(THEME_VALUE("data_fg"));

    charformat.setFontUnderline(true);
    charformat.setAnchor(true);
    charformat.setAnchorHref(DisassemblerDocument::encode(data));
}

void DisassemblerDocument::selectBlock(address_t address)
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

        if(!searchforward && (blockaddress < address))
            break;

        if(searchforward && (blockaddress > address))
            break;
    }

    if(!b.isValid())
        this->_textcursor.movePosition(searchforward ? QTextCursor::End : QTextCursor::Start);
    else
        this->_textcursor.setPosition(b.position());
}

bool DisassemblerDocument::isGenerated(address_t address)
{
    return this->_generated.find(address) != this->_generated.end();
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
