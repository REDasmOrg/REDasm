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

void DocumentTab::setCommand(ICommand* command)
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
    RDBlock block;
    if(!RDDocument_GetBlock(doc, item.address, &block)) return;

    QString hexdump = RD_HexDump(m_command->disassembler(), item.address, RDBlock_Size(&block));
    QByteArray dump = QByteArray::fromHex(hexdump.toUtf8());

    this->header("INSTRUCTION");

    m_indent = INDENT_BASE;
        this->line("assembler", RD_GetAssemblerInstruction(m_command->context().get(), block.address));
        this->line("rdil", RD_GetRDILInstruction(m_command->context().get(), block.address));
        this->line("hexdump", hexdump);
        this->line("bits", this->getBits(dump));
        this->line();
    m_indent = 0;
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

    RDDocument* doc = RDContext_GetDocument(m_command->context().get());

    this->header("ITEM");

    m_indent = INDENT_BASE;
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
