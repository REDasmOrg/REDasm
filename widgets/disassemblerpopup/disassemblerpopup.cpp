#include "disassemblerpopup.h"
#include <QLayout>
#include <QDebug>

DisassemblerPopup::DisassemblerPopup(REDasm::DisassemblerAPI *disassembler, QWidget *parent): QWidget(parent)
{
    m_popupwidget = new DisassemblerPopupWidget(disassembler, this);

    QVBoxLayout* vboxlayout = new QVBoxLayout(this);
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

    this->updateGeometry();
    this->move(QCursor::pos());
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
    QSize sz = document->size().toSize();

    this->resize(sz.width(), fm.height() * document->lineCount());
}
