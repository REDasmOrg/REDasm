#include "disassemblerblockitem.h"
#include "../../redasmsettings.h"
#include <QFontMetricsF>
#include <QApplication>
#include <QPainter>
#include <cmath>

#define BLOCK_MARGIN      4
#define DROP_SHADOW_SIZE  10
#define BLOCK_MARGINS     -BLOCK_MARGIN, 0, BLOCK_MARGIN, BLOCK_MARGIN

DisassemblerBlockItem::DisassemblerBlockItem(const RDFunctionBasicBlock* fbb, ICommand* command, RDGraphNode node, const RDGraph* g, QWidget *parent) : GraphViewItem(node, g, parent), m_basicblock(fbb), m_command(command), m_context(command->context())
{
    m_surface = new SurfaceRenderer(command->context(), RendererFlags_NoSegment | RendererFlags_NoSeparators | RendererFlags_NoIndent, parent);
    m_surface->setBaseColor(qApp->palette().color(QPalette::Base));
    connect(m_surface, &SurfaceRenderer::renderCompleted, this, [&]() { this->invalidate(); }, Qt::QueuedConnection);
    m_surface->goToAddress(RDFunctionBasicBlock_GetStartAddress(fbb));
    m_surface->resize(RDFunctionBasicBlock_ItemsCount(m_basicblock), 100);
}

const SurfaceRenderer* DisassemblerBlockItem::renderer() const { return m_surface; }
bool DisassemblerBlockItem::containsItem(const RDDocumentItem& item) const { return RDFunctionBasicBlock_Contains(m_basicblock, item.address); }

int DisassemblerBlockItem::currentLine() const
{
    RDDocumentItem item;

    if(m_command->getCurrentItem(&item) && this->containsItem(item))
    {
        RDDocument* doc = RDContext_GetDocument(m_context.get());

        //if(RDFunctionBasicBlock_GetStartItem(m_basicblock, &item))
            //return RDCursor_CurrentLine(m_command->cursor()) - RDDocument_ItemIndex(doc, &item);
    }

    return GraphViewItem::currentLine();
}

QSize DisassemblerBlockItem::size() const { return this->documentSize(); }
void DisassemblerBlockItem::mouseDoubleClickEvent(QMouseEvent*) { emit followRequested(this); }

void DisassemblerBlockItem::mousePressEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::LeftButton) m_surface->moveTo(e->localPos());
    else GraphViewItem::mousePressEvent(e);

    e->accept();
}

void DisassemblerBlockItem::mouseMoveEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::LeftButton)
    {
        e->accept();
        m_surface->select(e->localPos());
    }
}

QSize DisassemblerBlockItem::documentSize() const { return m_surface->size(); }

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

        painter->fillRect(r, m_surface->baseColor());
        if(m_surface) painter->drawPixmap(QPoint(0, 0), m_surface->pixmap());

        if(state & DisassemblerBlockItem::Selected)
            painter->setPen(QPen(qApp->palette().color(QPalette::Highlight), 2.0));
        else
            painter->setPen(QPen(qApp->palette().color(QPalette::WindowText), 1.5));

        painter->drawRect(r);
    painter->restore();
}
