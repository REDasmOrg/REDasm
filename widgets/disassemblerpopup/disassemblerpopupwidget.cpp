#include "disassemblerpopupwidget.h"
#include "../../redasmsettings.h"
#include <QGraphicsDropShadowEffect>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QPainter>

#define DEFAULT_ROW_COUNT 10

DisassemblerPopupWidget::DisassemblerPopupWidget(ListingDocumentRenderer *documentrenderer, const REDasm::DisassemblerPtr &disassembler, QWidget *parent): QPlainTextEdit(parent), m_disassembler(disassembler), m_document(disassembler->document()), m_documentrenderer(documentrenderer), m_index(-1), m_rows(DEFAULT_ROW_COUNT)
{
    QPalette palette = this->palette();
    palette.setColor(QPalette::Base, palette.color(QPalette::ToolTipBase));
    this->setPalette(palette);

    this->setFont(REDasmSettings::font());
    this->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    this->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    this->setTextInteractionFlags(Qt::NoTextInteraction);
    this->setCursor(Qt::ArrowCursor);

    QTextOption textoption;
    textoption.setWrapMode(QTextOption::NoWrap);
    this->document()->setDefaultTextOption(textoption);
    this->document()->setUndoRedoEnabled(false);
    this->document()->setDocumentMargin(0);

    QGraphicsDropShadowEffect* dropshadow = new QGraphicsDropShadowEffect(this);
    dropshadow->setBlurRadius(5);
    this->setGraphicsEffect(dropshadow);
}

bool DisassemblerPopupWidget::renderPopup(const std::string &word, int line)
{
    m_index = this->getIndexOfWord(word);

    if((m_index == REDasm::npos) || (m_index == line))
        return false;

    m_rows = DEFAULT_ROW_COUNT;
    this->renderPopup();
    return true;
}

void DisassemblerPopupWidget::moreRows()
{
    if((m_index + m_rows) > m_document->size())
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
    m_documentrenderer->render(m_index, m_rows, this->document());
}

size_t DisassemblerPopupWidget::getIndexOfWord(const std::string &word) const
{
    const REDasm::Symbol* symbol = m_document->symbol(word);

    if(!symbol)
        return REDasm::npos;

    if(symbol->isFunction())
        return m_document->functionIndex(symbol->address);

    return m_document->symbolIndex(symbol->address);
}
