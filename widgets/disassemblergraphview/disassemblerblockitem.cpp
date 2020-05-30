#include "disassemblerblockitem.h"
#include "../../redasmsettings.h"
#include <QFontMetricsF>
#include <QApplication>
#include <QPainter>
#include <cmath>

#define BLOCK_MARGIN      4
#define DROP_SHADOW_SIZE  10
#define BLOCK_MARGINS     -BLOCK_MARGIN, 0, BLOCK_MARGIN, BLOCK_MARGIN

DisassemblerBlockItem::DisassemblerBlockItem(const RDFunctionBasicBlock* fbb, IDisassemblerCommand* command, RDGraphNode node, QWidget *parent) : GraphViewItem(node, parent), m_basicblock(fbb), m_command(command)
{
    this->setupDocument();

    m_renderer = std::make_unique<DocumentRenderer>(&m_textdocument, command->disassembler(), command->cursor(), RendererFlags_NoSegment | RendererFlags_NoSeparators | RendererFlags_NoIndent);
    m_renderer->setStartOffset(RDFunctionBasicBlock_GetStartIndex(fbb));
    this->invalidate(false);

    QFontMetricsF fm(m_textdocument.defaultFont());
    m_charheight = fm.height();

    RDEvent_Subscribe(this, [](const RDEventArgs* e) {
        DisassemblerBlockItem* thethis = reinterpret_cast<DisassemblerBlockItem*>(e->owner);
        if((e->eventid != Event_CursorPositionChanged) || (e->sender != thethis->m_command->cursor())) return;
        thethis->invalidate();
    }, nullptr);
}

DisassemblerBlockItem::~DisassemblerBlockItem() { RDEvent_Unsubscribe(this); }
DocumentRenderer* DisassemblerBlockItem::renderer() const { return m_renderer.get(); }
bool DisassemblerBlockItem::containsItem(const RDDocumentItem& item) const { return RDFunctionBasicBlock_Contains(m_basicblock, item.address); }

int DisassemblerBlockItem::currentLine() const
{
    RDDocumentItem item;

    if(m_command->getCurrentItem(&item) && this->containsItem(item))
    {
        RDDocument* doc = RDDisassembler_GetDocument(m_command->disassembler());

        if(RDFunctionBasicBlock_GetStartItem(m_basicblock, &item))
            return RDCursor_CurrentLine(m_command->cursor()) - RDDocument_ItemIndex(doc, &item);
    }

    return GraphViewItem::currentLine();
}

QSize DisassemblerBlockItem::size() const { return this->documentSize(); }
void DisassemblerBlockItem::mouseDoubleClickEvent(QMouseEvent*) { emit followRequested(this); }

void DisassemblerBlockItem::mousePressEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::LeftButton) m_renderer->moveTo(e->localPos());
    else GraphViewItem::mousePressEvent(e);

    e->accept();
}

void DisassemblerBlockItem::mouseMoveEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::LeftButton)
    {
        e->accept();
        m_renderer->select(e->localPos());
    }
}

void DisassemblerBlockItem::invalidate(bool notify)
{
    m_textdocument.clear();
    m_renderer->render(RDFunctionBasicBlock_GetStartIndex(m_basicblock), RDFunctionBasicBlock_GetEndIndex(m_basicblock));
    m_textdocument.adjustSize();

    GraphViewItem::invalidate(notify);
}

QSize DisassemblerBlockItem::documentSize() const
{
    return { static_cast<int>(m_textdocument.size().width()),
             static_cast<int>(std::ceil(m_charheight * RDFunctionBasicBlock_ItemsCount(m_basicblock))) };
}

void DisassemblerBlockItem::render(QPainter *painter, size_t state)
{
    QRect r(QPoint(0, 0), this->documentSize());
    r.adjust(BLOCK_MARGINS);

    QColor shadow = painter->pen().color();
    shadow.setAlpha(127);

    painter->save();
        painter->translate(this->position());

        if(state & DisassemblerBlockItem::Selected) // Thicker shadow
            painter->fillRect(r.adjusted(DROP_SHADOW_SIZE, DROP_SHADOW_SIZE, DROP_SHADOW_SIZE + 2, DROP_SHADOW_SIZE + 2), shadow);
        else
            painter->fillRect(r.adjusted(DROP_SHADOW_SIZE, DROP_SHADOW_SIZE, DROP_SHADOW_SIZE, DROP_SHADOW_SIZE), shadow);

        painter->fillRect(r, qApp->palette().base());
        m_textdocument.drawContents(painter);

        if(state & DisassemblerBlockItem::Selected)
            painter->setPen(QPen(qApp->palette().color(QPalette::Highlight), 2.0));
        else
            painter->setPen(QPen(qApp->palette().color(QPalette::WindowText), 1.5));

        painter->drawRect(r);
    painter->restore();
}

void DisassemblerBlockItem::setupDocument()
{
    QTextOption textoption;
    textoption.setWrapMode(QTextOption::NoWrap);

    m_textdocument.setDefaultFont(REDasmSettings::font());
    m_textdocument.setDefaultTextOption(textoption);
    m_textdocument.setUndoRedoEnabled(false);
}
