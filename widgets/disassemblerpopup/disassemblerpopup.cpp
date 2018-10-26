#include "disassemblerpopup.h"
#include <QLayout>

#define POPUP_MARGIN 16

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

    QPoint pt = QCursor::pos();
    pt.rx() += POPUP_MARGIN;
    pt.ry() += POPUP_MARGIN;

    this->move(pt);
    this->updateGeometry();
    this->show();
}

void DisassemblerPopup::updateGeometry()
{
    QFontMetrics fm = this->fontMetrics();
    QTextDocument* document = m_popupwidget->document();

    this->resize(m_popuprenderer->maxWidth() + document->documentMargin(), fm.height() * document->lineCount() );
}
