#include "callgraphitem.h"
#include "../../redasm/disassembler/graph/callgraph.h"
#include <QFontDatabase>
#include <QFontMetrics>

CallGraphItem::CallGraphItem(REDasm::Graphing::Vertex *v, QObject *parent) : GraphItem(v, parent)
{
    m_font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
}

QSize CallGraphItem::size() const
{
    QFontMetrics fm(this->m_font);
    const REDasm::CallGraphVertex* cgv = static_cast<const REDasm::CallGraphVertex*>(this->vertex());
    return QSize(fm.width(QString::fromStdString(cgv->symbol->name)) + (fm.width(" ") * 2), fm.height() * 2);
}

void CallGraphItem::paint(QPainter *painter)
{
    const REDasm::CallGraphVertex* cgv = static_cast<const REDasm::CallGraphVertex*>(this->vertex());
    QTextOption textoption(Qt::AlignCenter);

    painter->setFont(this->m_font);
    painter->drawText(QRect(this->position(), this->size()),
                      QString::fromStdString(cgv->symbol->name), textoption);

    GraphItem::paint(painter);
}
