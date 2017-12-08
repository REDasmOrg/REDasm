#include "functionblockitem.h"
#include <QStyleOptionGraphicsItem>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QPainter>

FunctionBlockItem::FunctionBlockItem(REDasm::Disassembler *disassembler, const QString &theme) : QGraphicsTextItem()
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setPointSize(12);
    font.setStyleHint(QFont::TypeWriter);

    this->setFont(font);

    this->_graphdocument = new DisassemblerGraphDocument(disassembler, theme, this->document());
}

FunctionBlockItem::~FunctionBlockItem()
{
    this->_graphdocument->deleteLater();
    this->_graphdocument = NULL;
}

void FunctionBlockItem::append(const REDasm::InstructionPtr &instruction)
{
    this->_graphdocument->generate(instruction, this->textCursor());
}

void FunctionBlockItem::append(const REDasm::SymbolPtr &symbol)
{
    this->_graphdocument->generate(symbol, this->textCursor());
}

void FunctionBlockItem::paint(QPainter *painter, const QStyleOptionGraphicsItem *option, QWidget *widget)
{
    QGraphicsTextItem::paint(painter, option, widget);

    painter->setPen(QColor(Qt::black));
    painter->drawRect(option->rect);
}
