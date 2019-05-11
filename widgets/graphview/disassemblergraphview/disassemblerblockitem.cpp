#include "disassemblerblockitem.h"
#include "../../../redasmsettings.h"
#include <QApplication>
#include <QFontMetricsF>
#include <QPainter>
#include <QDebug>

#define BLOCK_MARGIN 4
#define DROP_SHADOW_SIZE  10
#define BLOCK_MARGINS -BLOCK_MARGIN, 0, BLOCK_MARGIN, BLOCK_MARGIN

DisassemblerBlockItem::DisassemblerBlockItem(const REDasm::Graphing::FunctionBasicBlock *fbb, const REDasm::DisassemblerPtr &disassembler, const REDasm::Graphing::Node &node, QWidget *parent) : GraphViewItem(node, parent), m_basicblock(fbb), m_disassembler(disassembler)
{
    this->setupDocument();

    m_renderer = std::make_unique<ListingDocumentRenderer>(disassembler.get());
    m_renderer->setFirstVisibleLine(fbb->startidx);
    m_renderer->setFlags(ListingDocumentRenderer::HideSegmentName);
    this->invalidate(false);

    QFontMetricsF fm(m_document.defaultFont());
    m_charheight = fm.height();

    EVENT_CONNECT(m_disassembler->document()->cursor(), positionChanged, this, [&]() {
        if(!m_basicblock->contains(m_disassembler->document()->cursor()->currentLine()))
            return;

        this->invalidate();
    });
}

DisassemblerBlockItem::~DisassemblerBlockItem() { EVENT_DISCONNECT(m_disassembler->document()->cursor(), positionChanged, this); }
std::string DisassemblerBlockItem::currentWord() { return m_renderer->getCurrentWord(); }
ListingDocumentRenderer *DisassemblerBlockItem::renderer() const { return m_renderer.get(); }
bool DisassemblerBlockItem::containsIndex(s64 index) const { return m_basicblock->contains(index); }

int DisassemblerBlockItem::currentLine() const
{
    const REDasm::ListingCursor* cursor = m_renderer->document()->cursor();

    if(this->containsIndex(cursor->currentLine()))
        return cursor->currentLine() - m_basicblock->startidx;

    return GraphViewItem::currentLine();
}

QSize DisassemblerBlockItem::size() const { return this->documentSize(); }

void DisassemblerBlockItem::mouseDoubleClickEvent(QMouseEvent *e)
{
    emit followRequested(e->localPos());
    e->accept();
}

void DisassemblerBlockItem::mousePressEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::LeftButton)
        m_renderer->moveTo(e->localPos());
    else
        GraphViewItem::mousePressEvent(e);

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
    m_document.clear();
    m_renderer->render(m_basicblock->startidx, m_basicblock->count(), &m_document);
    m_document.adjustSize();

    GraphViewItem::invalidate(notify);
}

QSize DisassemblerBlockItem::documentSize() const
{
    return { static_cast<int>(m_document.size().width()),
             static_cast<int>(std::ceil(m_charheight * m_basicblock->count())) };
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
        m_document.drawContents(painter);

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

    m_document.setDefaultFont(REDasmSettings::font());
    m_document.setDefaultTextOption(textoption);
    m_document.setUndoRedoEnabled(false);
}
