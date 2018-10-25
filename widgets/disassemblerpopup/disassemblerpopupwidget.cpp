#include "disassemblerpopupwidget.h"
#include <QGraphicsDropShadowEffect>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QPainter>

#define DEFAULT_ROW_COUNT 10

DisassemblerPopupWidget::DisassemblerPopupWidget(REDasm::DisassemblerAPI* disassembler, QWidget *parent): QPlainTextEdit(parent), m_disassembler(disassembler), m_index(-1), m_rows(DEFAULT_ROW_COUNT)
{
    m_popuprenderer = new ListingPopupRenderer(disassembler);
    m_document = disassembler->document();

    QPalette palette = this->palette();
    palette.setColor(QPalette::Background, palette.color(QPalette::ToolTipBase));
    this->setPalette(palette);

    this->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    this->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    this->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    this->setTextInteractionFlags(Qt::NoTextInteraction);
    this->setCursor(Qt::ArrowCursor);
    this->setLineWrapMode(QPlainTextEdit::NoWrap);
    this->setAutoFillBackground(true);

    QGraphicsDropShadowEffect* dropshadow = new QGraphicsDropShadowEffect(this);
    dropshadow->setBlurRadius(5);
    this->setGraphicsEffect(dropshadow);
}

bool DisassemblerPopupWidget::renderPopup(const std::string &word)
{
    m_index = this->getIndexOfWord(word);

    if(m_index == -1)
        return false;

    this->clear();
    m_popuprenderer->render(m_index, m_rows, this->document());
    return true;
}

int DisassemblerPopupWidget::getIndexOfWord(const std::string &word) const
{
    REDasm::SymbolPtr symbol = m_document->symbol(word);

    if(!symbol)
        return -1;

    return m_document->indexOf(symbol->address);
}
