#include "documenttab.h"
#include "ui_documenttab.h"
#include "../logsyntaxhighlighter.h"
#include "../../../redasmsettings.h"
#include "../../../renderer/surfaceqt.h"
#include <climits>

#define INDENT_BASE   2
#define VALUE_COLUMN  15
#define HEADER_STRING "-"
#define NOT_AVAILABLE "N/A"
#define STR(x) #x
#define RETURN_CASE_OF(x) case x: return #x

#define CHECK_FLAG(s, x, f) \
    if(x & f) { \
        if(!s.isEmpty()) s += " | "; \
        s += #f; \
    }

#define CHECK_HAS_FLAG(s, x, f) \
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

void DocumentTab::setContext(const RDContextPtr& ctx)
{
    m_context = ctx;
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

QString DocumentTab::blockType(const RDBlock* block) const
{
    switch(block->type)
    {
        RETURN_CASE_OF(BlockType_Code);
        RETURN_CASE_OF(BlockType_Data);
        RETURN_CASE_OF(BlockType_String);
        RETURN_CASE_OF(BlockType_Unknown);
        default: break;
    }

    return "???";
}

QString DocumentTab::segmentFlags(const RDSegment* segment) const
{
    QString s;
    CHECK_HAS_FLAG(s, segment, SegmentFlags_Code);
    CHECK_HAS_FLAG(s, segment, SegmentFlags_Data);
    CHECK_HAS_FLAG(s, segment, SegmentFlags_Bss);
    return s.isEmpty() ? STR(SegmentFlags_None) : s;
}

QString DocumentTab::addressFlags(RDDocument* doc, rd_address address) const
{
    QString s;
    rd_flag flags = RDDocument_GetFlags(doc, address);

    CHECK_FLAG(s, flags, AddressFlags_Explored);
    CHECK_FLAG(s, flags, AddressFlags_Location);
    CHECK_FLAG(s, flags, AddressFlags_Exported);
    CHECK_FLAG(s, flags, AddressFlags_Imported);
    CHECK_FLAG(s, flags, AddressFlags_Function);
    CHECK_FLAG(s, flags, AddressFlags_AsciiString);
    CHECK_FLAG(s, flags, AddressFlags_WideString);
    CHECK_FLAG(s, flags, AddressFlags_Pointer);
    CHECK_FLAG(s, flags, AddressFlags_NoReturn);
    CHECK_FLAG(s, flags, AddressFlags_Type);
    CHECK_FLAG(s, flags, AddressFlags_TypeField);
    CHECK_FLAG(s, flags, AddressFlags_TypeEnd);

    return s.isEmpty() ? STR(AddressFlags_None) : s;
}

QString DocumentTab::padHexDump(const QString& hexdump) const
{
    if(hexdump.size() % 2) return hexdump;

    QString phexdump;

    for(int i = 0; i < hexdump.size(); i += 2)
    {
        if(!phexdump.isEmpty()) phexdump += " ";
        phexdump += hexdump.midRef(i, 2);
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

QString DocumentTab::joinAddressList(const rd_address* addresslist, size_t c) const
{
    if(!c) return NOT_AVAILABLE;

    QString s;

    for(size_t i = 0; i < c; i++)
    {
        if(!s.isEmpty()) s += ", ";
        s += RD_ToHex(addresslist[i]);
    }

    return s;
}

void DocumentTab::displayInstructionInformation(RDDocument* doc, rd_address address)
{
    RDBlock block;
    if(!RDDocument_AddressToBlock(doc, address, &block)) return;

    QString hexdump = RD_HexDump(m_context.get(), address, RDBlock_Size(&block));
    QByteArray dump = QByteArray::fromHex(hexdump.toUtf8());
    const char* assemblerid = RDDocument_GetAddressAssembler(doc, address);

    this->header("INSTRUCTION");

    m_indent = INDENT_BASE;
        this->string("assembler", assemblerid ? assemblerid : "???");
        this->line("instruction", RD_GetAssemblerInstruction(m_context.get(), block.address));
        this->line("rdil", RD_GetRDILInstruction(m_context.get(), block.address));
        this->line("rdilformat", RD_GetRDILFormat(m_context.get(), block.address));
        this->line("hexdump", hexdump);
        this->line("bits", this->getBits(dump));
        this->line();
    m_indent = 0;
}

void DocumentTab::displayNetInformation(rd_address address)
{
    const RDNet* net = RDContext_GetNet(m_context.get());
    auto* n = RDNet_FindNode(net, address);
    if(!n) return;

    auto* prevnode = RDNet_GetPrevNode(net, n);
    auto* nextnode = RDNet_GetNextNode(net, n);

    const rd_address *from = nullptr, *branchesfalse = nullptr, *branchestrue;
    size_t cfrom = RDNetNode_GetFrom(n, &from);
    size_t cfalse = RDNetNode_GetBranchesFalse(n, &branchesfalse);
    size_t ctrue = RDNetNode_GetBranchesTrue(n, &branchestrue);

    this->header("NET");

    m_indent = INDENT_BASE;
        this->line("prev", prevnode ? RD_ToHex(RDNetNode_GetAddress(prevnode)) : NOT_AVAILABLE);
        this->line("next", nextnode ? RD_ToHex(RDNetNode_GetAddress(nextnode)) : NOT_AVAILABLE);
        this->line("from", this->joinAddressList(from, cfrom));
        this->line("branchfalse", this->joinAddressList(branchesfalse, cfalse));
        this->line("branchtrue", this->joinAddressList(branchestrue, ctrue));
    m_indent = 0;
}

void DocumentTab::displayInformation()
{
    ui->pteInfo->clear();

    RDSurface* activesurface = RDContext_GetActiveSurface(m_context.get());
    if(!m_context || !activesurface) return;

    const auto* surface = reinterpret_cast<const SurfaceQt*>(RDSurface_GetUserData(activesurface));

    rd_address address = surface->currentAddress();
    if(address == RD_NVAL) return;

    RDDocument* doc = RDContext_GetDocument(m_context.get());
    this->header("GENERAL");

    m_indent = INDENT_BASE;
        RDSegment segment;
        if(RDDocument_AddressToSegment(doc, address, &segment))
            this->line("segment", QString::fromUtf8(segment.name));
        else
            this->line("segment", "???");

        auto loc = RD_Offset(m_context.get(), address);
        this->line("offset", loc.valid ? RD_ToHex(loc.offset) : "???");
        this->line("address", RD_ToHex(address));
        this->line("flags", this->addressFlags(doc, address));

        const char* label = RDDocument_GetLabel(doc, address);
        if(label) this->line("label", label);

        RDBlock block;

        if(RDDocument_AddressToBlock(doc, address, &block))
        {
            this->line("blocktype", this->blockType(&block));
            this->line("blockstart", RD_ToHex(block.start));
            this->line("blockend", RD_ToHex(block.end));
            this->line("blocksize", RD_ToHex(RDBlock_Size(&block)));
        }

        this->line();
    m_indent = 0;

    this->displayInstructionInformation(doc, address);
    this->displayNetInformation(address);
}
