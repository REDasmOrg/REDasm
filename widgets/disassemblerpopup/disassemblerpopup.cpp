#include "disassemblerpopup.h"
#include <QLayout>

DisassemblerPopup::DisassemblerPopup(REDasm::DisassemblerAPI *disassembler, QWidget *parent): QWidget(parent)
{
    m_popuprenderer = new ListingPopupRenderer(disassembler);
    m_popupwidget = new DisassemblerPopupWidget(m_popuprenderer, disassembler, this);

    QVBoxLayout* vboxlayout = new QVBoxLayout(this);
    vboxlayout->setContentsMargins(0, 0, 0, 0);
    vboxlayout->addWidget(m_popupwidget);
    this->setLayout(vboxlayout);

    this->setFocusPolicy(Qt::NoFocus);
    this->setAttribute(Qt::WA_TranslucentBackground);
    this->setWindowFlags(Qt::ToolTip);
}

DisassemblerPopup::~DisassemblerPopup() { delete m_popuprenderer; }

void DisassemblerPopup::popup(const std::string &word)
{
    if(!m_popupwidget->renderPopup(word))
    {
        this->hide();
        return;
    }

    this->move(QCursor::pos());
    this->updateGeometry();
    this->show();
}

void DisassemblerPopup::wheelEvent(QWheelEvent *e)
{
    QWidget::wheelEvent(e);
}

void DisassemblerPopup::updateGeometry()
{
    QFontMetrics fm = this->fontMetrics();
    QTextDocument* document = m_popupwidget->document();
    this->resize(m_popuprenderer->maxWidth(), fm.height() * document->lineCount());
}
