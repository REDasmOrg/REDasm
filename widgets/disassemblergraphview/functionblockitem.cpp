#include "functionblockitem.h"
#include <QStyleOptionGraphicsItem>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QPainter>

FunctionBlockItem::FunctionBlockItem(REDasm::Disassembler *disassembler, const QString &theme, REDasm::Graphing::Vertex* v, QObject *parent) : GraphTextItem(v, parent)
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
