#include "callgraphitem.h"
#include <rdapi/rdapi.h>
#include <QApplication>
#include <QFontMetrics>

CallGraphItem::CallGraphItem(const RDContextPtr& ctx, RDGraphNode node, const RDGraph* g, QObject *parent) : GraphViewItem(node, g, parent), m_context(ctx)
{
    m_palette = qApp->palette();
    auto* data = RDGraph_GetData(g, node);

    if(data)
    {
        auto* doc = RDContext_GetDocument(m_context.get());
        auto* cgitem = reinterpret_cast<RDCallGraphItem*>(data->p_data);
        auto* netnode = RDCallGraphItem_GetNetNode(cgitem);
        m_address = RDNetNode_GetAddress(netnode);
        const char* n = RDDocument_GetLabel(doc, m_address);
        m_label = n ? n : RD_ToHex(m_address);
    }
    else
        m_label = "???";

    auto fm = qApp->fontMetrics();
    m_size = { fm.width(m_label) + (BLOCK_MARGIN * 2), fm.height() * 2 };
}

void CallGraphItem::render(QPainter* painter, size_t state)
{
    QRect r(this->position(), this->size());

    if(state == CallGraphItem::Selected) painter->setPen(QPen(m_palette.brush(QPalette::WindowText), 2));
    else painter->setPen(QPen(m_palette.brush(QPalette::WindowText), 1));

    painter->drawRect(r);
    painter->drawText(r, Qt::AlignCenter, m_label);
}

QSize CallGraphItem::size() const { return m_size; }

void CallGraphItem::mouseDoubleClickEvent(QMouseEvent*)
{
    if(m_address != RD_NVAL)
        Q_EMIT fetchMore(m_address);
}
