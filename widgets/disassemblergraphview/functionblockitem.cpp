#include "functionblockitem.h"
#include <QtGui>
#include "../../redasm/disassembler/graph/functiongraph.h"

FunctionBlockItem::FunctionBlockItem(REDasm::DisassemblerAPI *disassembler, REDasm::Graphing::Vertex* v, QObject *parent) : GraphTextItem(v, parent), m_disassembler(disassembler)
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setStyleHint(QFont::TypeWriter);
    this->setFont(font);
}

void FunctionBlockItem::append(const REDasm::InstructionPtr &instruction) { }
void FunctionBlockItem::append(const REDasm::SymbolPtr &symbol) { }
int FunctionBlockItem::titleHeight() const { QFontMetrics fm(this->font()); return fm.height() + 2; }
QPoint FunctionBlockItem::origin() const { return GraphTextItem::origin() + QPoint(0, this->titleHeight()); }

QSize FunctionBlockItem::size() const
{
    QSize sz = GraphTextItem::size();
    sz.rheight() += this->titleHeight();
    return sz;
}

void FunctionBlockItem::paint(QPainter *painter)
{
    /*
    int th = this->titleHeight();
    QPoint pos = this->position(), px = QPoint(pos.x(), pos.y() + th), pwx = QPoint(pos.x() + this->width(), pos.y() + th);
    QRect tr(pos, pwx);

    const REDasm::FunctionGraphVertex* fgv = static_cast<const REDasm::FunctionGraphVertex*>(this->vertex());
    REDasm::SymbolPtr symbol = this->_disassembler->symbolTable()->symbol(fgv->start);
    QTextOption topt(Qt::AlignLeft | Qt::AlignVCenter);

    QFontMetrics fm(this->font());
    QString title = QString("%1.%2: %3").arg(fgv->layer())
                                        .arg(fgv->index())
                                        .arg(QString::fromStdString(symbol ? symbol->name : REDasm::hex(fgv->start)));

    painter->save();
        painter->setFont(this->font());
        painter->setPen(QPen(Qt::black, 2));
        painter->fillRect(tr, Qt::lightGray);

        tr.adjust(2, 2, -2, -2);
        painter->drawText(tr, fm.elidedText(title, Qt::ElideRight, tr.width()), topt);
        painter->drawLine(px, pwx);
    painter->restore();

    */
    GraphTextItem::paint(painter);
}
