#include "callgraphitem.h"
#include "../../redasm/disassembler/graph/callgraph.h"
#include <QFontDatabase>
#include <QFontMetrics>

CallGraphItem::CallGraphItem(REDasm::Graphing::Vertex *v, QObject *parent) : GraphItem(v, parent)
{
    this->_font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
}

QSize CallGraphItem::size() const
{
    QFontMetrics fm(this->_font);
    const REDasm::CallGraphVertex* cgv = static_cast<const REDasm::CallGraphVertex*>(this->vertex());
    return QSize(fm.width(QString::fromStdString(cgv->symbol->name)) + (fm.width(" ") * 2), fm.height() * 2);
}

void CallGraphItem::paint(QPainter *painter)
{
    const REDasm::CallGraphVertex* cgv = static_cast<const REDasm::CallGraphVertex*>(this->vertex());
    QTextOption textoption(Qt::AlignCenter);

    painter->setFont(this->_font);
    painter->drawText(QRect(this->position(), this->size()),
                      QString::fromStdString(cgv->symbol->name), textoption);

    GraphItem::paint(painter);
}
