#include "disassemblerpopupwidget.h"
#include <QGraphicsDropShadowEffect>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QPainter>
#include <QDebug>

#define DEFAULT_ROW_COUNT 10

DisassemblerPopupWidget::DisassemblerPopupWidget(ListingPopupRenderer *popuprenderer, REDasm::DisassemblerAPI* disassembler, QWidget *parent): QPlainTextEdit(parent), m_popuprenderer(popuprenderer), m_disassembler(disassembler), m_index(-1), m_rows(DEFAULT_ROW_COUNT)
{
    m_document = disassembler->document();

    QPalette palette = this->palette();
    palette.setColor(QPalette::Base, palette.color(QPalette::ToolTipBase));
    this->setPalette(palette);

    this->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    this->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    this->setTextInteractionFlags(Qt::NoTextInteraction);
    this->setCursor(Qt::ArrowCursor);

    QTextOption textoption;
    textoption.setWrapMode(QTextOption::NoWrap);
    this->document()->setDefaultFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    this->document()->setDefaultTextOption(textoption);
    this->document()->setUndoRedoEnabled(false);
    this->document()->setDocumentMargin(0);

    QGraphicsDropShadowEffect* dropshadow = new QGraphicsDropShadowEffect(this);
    dropshadow->setBlurRadius(5);
    this->setGraphicsEffect(dropshadow);
}

bool DisassemblerPopupWidget::renderPopup(const std::string &word)
{
    m_index = this->getIndexOfWord(word);

    if(m_index == -1)
        return false;

    m_rows = DEFAULT_ROW_COUNT;
    this->renderPopup();
    return true;
}

void DisassemblerPopupWidget::moreRows()
{
    if(m_index + m_rows > static_cast<int>(m_document->size()))
        return;

    m_rows++;
    this->renderPopup();
}

void DisassemblerPopupWidget::lessRows()
{
    if(m_rows == 1)
        return;

    m_rows--;
    this->renderPopup();
}

int DisassemblerPopupWidget::rows() const { return m_rows; }

void DisassemblerPopupWidget::renderPopup()
{
    this->clear();
    m_popuprenderer->render(m_index, m_rows, this->document());
}

int DisassemblerPopupWidget::getIndexOfWord(const std::string &word) const
{
    REDasm::SymbolPtr symbol = m_document->symbol(word);

    if(!symbol)
        return -1;

    if(symbol->isFunction())
        return m_document->functionIndex(symbol->address);

    return m_document->indexOf(symbol->address);
}
