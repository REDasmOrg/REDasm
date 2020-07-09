#include "documenttab.h"
#include "ui_documenttab.h"
#include "../logsyntaxhighlighter.h"
#include "../../../redasmsettings.h"
#include <climits>

#define INDENT_BASE   2
#define VALUE_COLUMN  15
#define HEADER_STRING "-"
#define STR(x) #x
#define RETURN_CASE_OF(x) case x: return #x

#define CHECK_FLAG(s, x, f) \
    if(HAS_FLAG(x, f)) { \
        if(!s.isEmpty()) s += " | "; \
        s += #f; \
    }

DocumentTab::DocumentTab(QWidget *parent) : QWidget(parent), ui(new Ui::DocumentTab)
{
    ui->setupUi(this);
    ui->pteInfo->setFont(REDasmSettings::font());

    new LogSyntaxHighlighter(ui->pteInfo->document());
}

DocumentTab::~DocumentTab() { delete ui; }

void DocumentTab::setCommand(IDisassemblerCommand* command)
{
    m_command = command;
    this->updateInformation();
}

void DocumentTab::updateInformation()
{
    this->displayInformation();
    ui->pteInfo->moveCursor(QTextCursor::Start);
}

DocumentTab &DocumentTab::line(const QString &s1, const QString &s2)
{
    QString padding;

    if(s1.size() < VALUE_COLUMN) padding = QString(" ").repeated(VALUE_COLUMN - s1.size());
    else padding = "";

    return this->line(QString("%1%2:%3%4").arg(QString(" ").repeated(m_indent), s1, padding, s2));
}

DocumentTab& DocumentTab::line(const QString &s) { ui->pteInfo->appendPlainText(s); return *this; }
DocumentTab &DocumentTab::header(const QString &s) { return this->line(s).line(QString(HEADER_STRING).repeated(s.size())); }
DocumentTab &DocumentTab::string(const QString &k, const QString &s) { return this->line(k, QString("\"%1\"").arg(s)); }

QString DocumentTab::itemType(const RDDocumentItem& item) const
{
    switch(item.type)
    {
        RETURN_CASE_OF(DocumentItemType_Segment);
        RETURN_CASE_OF(DocumentItemType_Empty);
        RETURN_CASE_OF(DocumentItemType_Function);
        RETURN_CASE_OF(DocumentItemType_Type);
        RETURN_CASE_OF(DocumentItemType_Symbol);
        RETURN_CASE_OF(DocumentItemType_Meta);
        RETURN_CASE_OF(DocumentItemType_Instruction);
        RETURN_CASE_OF(DocumentItemType_Unexplored);
        RETURN_CASE_OF(DocumentItemType_Separator);
        default: break;
    }

    return QString::number(item.type);
}

QString DocumentTab::segmentFlags(const RDSegment* segment) const
{
    QString s;
    CHECK_FLAG(s, segment, SegmentFlags_Code);
    CHECK_FLAG(s, segment, SegmentFlags_Data);
    CHECK_FLAG(s, segment, SegmentFlags_Bss);
    return s.isEmpty() ? STR(SegmentFlags_None) : s;
}

QString DocumentTab::instructionType(const RDInstruction* instruction) const
{
    switch(instruction->type)
    {
        RETURN_CASE_OF(InstructionType_None);
        RETURN_CASE_OF(InstructionType_Invalid);
        RETURN_CASE_OF(InstructionType_Ret);
        RETURN_CASE_OF(InstructionType_Nop);
        RETURN_CASE_OF(InstructionType_Jump);
        RETURN_CASE_OF(InstructionType_Call);
        RETURN_CASE_OF(InstructionType_Add);
        RETURN_CASE_OF(InstructionType_Sub);
        RETURN_CASE_OF(InstructionType_Mul);
        RETURN_CASE_OF(InstructionType_Div);
        RETURN_CASE_OF(InstructionType_Mod);
        RETURN_CASE_OF(InstructionType_Lsh);
        RETURN_CASE_OF(InstructionType_Rsh);
        RETURN_CASE_OF(InstructionType_And);
        RETURN_CASE_OF(InstructionType_Or);
        RETURN_CASE_OF(InstructionType_Xor);
        RETURN_CASE_OF(InstructionType_Not);
        RETURN_CASE_OF(InstructionType_Push);
        RETURN_CASE_OF(InstructionType_Pop);
        RETURN_CASE_OF(InstructionType_Compare);
        RETURN_CASE_OF(InstructionType_Load);
        RETURN_CASE_OF(InstructionType_Store);
        default: break;
    }

    return QString::number(instruction->type);
}

QString DocumentTab::instructionFlags(const RDInstruction* instruction) const
{
    QString s;
    CHECK_FLAG(s, instruction, InstructionFlags_Weak);
    CHECK_FLAG(s, instruction, InstructionFlags_Conditional);
    CHECK_FLAG(s, instruction, InstructionFlags_Privileged);
    CHECK_FLAG(s, instruction, InstructionFlags_Stop);
    return s.isEmpty() ? STR(InstructionFlags_None) : s;
}

QString DocumentTab::operandType(const RDOperand* operand) const
{
    switch(operand->type)
    {
        RETURN_CASE_OF(OperandType_Void);
        RETURN_CASE_OF(OperandType_Constant);
        RETURN_CASE_OF(OperandType_Register);
        RETURN_CASE_OF(OperandType_Immediate);
        RETURN_CASE_OF(OperandType_Memory);
        RETURN_CASE_OF(OperandType_Displacement);
        default: break;
    }

    return QString::number(operand->type);
}

QString DocumentTab::symbolType(const RDSymbol* symbol) const
{
    switch(symbol->type)
    {
        RETURN_CASE_OF(SymbolType_None);
        RETURN_CASE_OF(SymbolType_Data);
        RETURN_CASE_OF(SymbolType_String);
        RETURN_CASE_OF(SymbolType_Label);
        RETURN_CASE_OF(SymbolType_Function);
        RETURN_CASE_OF(SymbolType_Import);
        default: break;
    }

    return QString::number(symbol->type);
}

QString DocumentTab::symbolFlags(const RDSymbol* symbol) const
{
    QString s;
    CHECK_FLAG(s, symbol, SymbolFlags_Weak);
    CHECK_FLAG(s, symbol, SymbolFlags_Export);
    CHECK_FLAG(s, symbol, SymbolFlags_EntryPoint);
    CHECK_FLAG(s, symbol, SymbolFlags_AsciiString);
    CHECK_FLAG(s, symbol, SymbolFlags_WideString);
    CHECK_FLAG(s, symbol, SymbolFlags_Pointer);
    CHECK_FLAG(s, symbol, SymbolFlags_TableItem);
    return s.isEmpty() ? STR(InstructionFlags_None) : s;
}

QString DocumentTab::padHexDump(const QString& hexdump) const
{
    if(hexdump.size() % 2) return hexdump;

    QString phexdump;

    for(int i = 0; i < hexdump.size(); i += 2)
    {
        if(!phexdump.isEmpty()) phexdump += " ";
        phexdump += hexdump.mid(i, 2);
    }

    return phexdump;
}

QString DocumentTab::getBits(const QByteArray& ba) const
{
    const int charbit_m = CHAR_BIT - 1;

    QString bits;

    for(int i = 0; i < ba.size(); i++)
    {
        uchar byte = ba[i];

        for(int b = 0; b < CHAR_BIT; b++)
            bits.append((byte & (1 << (charbit_m - b))) ? "1" : "0");

        if(i < ba.size() - 1) bits.append(" ");
    }

    return bits;
}

void DocumentTab::displayInstructionInformation(RDDocument* doc, const RDDocumentItem& item)
{
    InstructionLock instruction(doc, item.address);
    if(!instruction) return;

    QString hexdump = RD_HexDump(m_command->disassembler(), item.address, instruction->size);
    QByteArray dump = QByteArray::fromHex(hexdump.toUtf8());

    this->header("INSTRUCTION");

    m_indent = INDENT_BASE;
        this->line("id", QString::number(instruction->id, 16));
        this->line("address", RD_ToHex(instruction->address));
        this->string("mnemonic", instruction->mnemonic);
        this->line("type", this->instructionType(*instruction));
        this->line("flags", this->instructionFlags(*instruction));
        this->line("size", QString("%1 byte(s)").arg(instruction->size));
        this->line("operands", QString::number(instruction->operandscount));
        this->line("hexdump", hexdump);
        this->line("bits", this->getBits(dump));
        this->line();
    m_indent = 0;

    for(size_t i = 0; i < instruction->operandscount; i++)
    {
        if(i) this->line();
        const RDOperand& op = instruction->operands[i];
        this->header(QString("OPERAND %1").arg(i));

        m_indent = INDENT_BASE;

            this->line("type", this->operandType(&op));

            switch(op.type)
            {
                case OperandType_Register: this->line("reg", QString::number(op.reg)); break;

                case OperandType_Constant:
                case OperandType_Immediate:
                case OperandType_Memory: this->line("u_value", QString::number(op.u_value, 16)); break;

                case OperandType_Displacement:
                    this->line("base", QString::number(op.base));
                    this->line("index", QString::number(op.index));
                    this->line("scale", QString::number(op.scale));
                    this->line("displacement", QString::number(op.displacement, 16));
                    break;

                default: break;
            }

        m_indent = 0;
    }
}

void DocumentTab::displaySymbolInformation(RDDocument* doc, const RDDocumentItem& item)
{
    RDSymbol symbol;
    if(!RDDocument_GetSymbolByAddress(doc, item.address, &symbol)) return;

    const char* name = RDDocument_GetSymbolName(doc, symbol.address);
    if(!name) return;

    this->header("SYMBOL");

    m_indent = INDENT_BASE;
        this->line("address", RD_ToHex(symbol.address));
        this->line("type", this->symbolType(&symbol));
        this->line("flags", this->symbolFlags(&symbol));
        this->line();
    m_indent = 0;
}

void DocumentTab::displayInformation()
{
    ui->pteInfo->clear();
    if(!m_command) return;

    RDDocumentItem item;
    if(!m_command->getCurrentItem(&item)) return;

    RDDocument* doc = RDDisassembler_GetDocument(m_command->disassembler());

    this->header("ITEM");

    m_indent = INDENT_BASE;
        this->line("document_index", QString::number(RDDocument_ItemIndex(doc, &item)));
        this->line("address", RD_ToHex(item.address));
        this->line("type", this->itemType(item));
        this->line("index", QString::number(item.index));
        this->line();
    m_indent = 0;

    switch(item.type)
    {
        case DocumentItemType_Symbol: this->displaySymbolInformation(doc, item); break;
        case DocumentItemType_Instruction: this->displayInstructionInformation(doc, item); break;
        default: break;
    }
}
