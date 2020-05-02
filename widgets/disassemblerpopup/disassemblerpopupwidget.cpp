#include "disassemblerpopupwidget.h"
#include "../../redasmsettings.h"
#include <QGraphicsDropShadowEffect>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QPainter>

#define DEFAULT_ROW_COUNT 10

DisassemblerPopupWidget::DisassemblerPopupWidget(DocumentRenderer* renderer, RDDisassembler* disassembler, QWidget *parent): QPlainTextEdit(parent), m_disassembler(disassembler), m_renderer(renderer), m_rows(DEFAULT_ROW_COUNT)
{
    this->setDocument(renderer->textDocument());
    m_document = RDDisassembler_GetDocument(disassembler);

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

bool DisassemblerPopupWidget::renderPopup(const QString& word, size_t line)
{
    m_index = this->getIndexOfWord(word);

    if((m_index == RD_NPOS) || (m_index == line))
        return false;

    m_rows = DEFAULT_ROW_COUNT;
    this->renderPopup();
    return true;
}

void DisassemblerPopupWidget::moreRows()
{
    if((m_index + m_rows) > RDDocument_ItemsCount(m_document)) return;
    m_rows++;
    this->renderPopup();
}

void DisassemblerPopupWidget::lessRows()
{
    if(m_rows == 1) return;
    m_rows--;
    this->renderPopup();
}

int DisassemblerPopupWidget::rows() const { return m_rows; }
void DisassemblerPopupWidget::renderPopup() { m_renderer->render(m_index, m_index + m_rows); }

size_t DisassemblerPopupWidget::getIndexOfWord(const QString& word) const
{
    RDSymbol symbol;
    if(!RDDocument_GetSymbolByName(m_document, qUtf8Printable(word), &symbol)) return RD_NPOS;

    if(symbol.type == SymbolType_Function) return RDDocument_FunctionIndex(m_document, symbol.address);
    return RDDocument_SymbolIndex(m_document, symbol.address);
}
