#include "disassemblerpopup.h"
#include <QLayout>
#include <cmath>

#define POPUP_MARGIN 16

DisassemblerPopup::DisassemblerPopup(const REDasm::DisassemblerPtr &disassembler, QWidget *parent): QWidget(parent)
{
    m_documentrenderer = new ListingDocumentRenderer();
    m_popupwidget = new DisassemblerPopupWidget(m_documentrenderer, disassembler, this);

    QVBoxLayout* vboxlayout = new QVBoxLayout(this);
    vboxlayout->setContentsMargins(0, 0, 0, 0);
    vboxlayout->addWidget(m_popupwidget);
    this->setLayout(vboxlayout);

    this->setAttribute(Qt::WA_TranslucentBackground);
    this->setWindowFlags(Qt::Popup);
    this->setMouseTracking(true);
    this->setMinimumHeight(0);
    this->setMinimumWidth(0);
}

DisassemblerPopup::~DisassemblerPopup() { delete m_documentrenderer; }

void DisassemblerPopup::popup(const REDasm::String &word, int line)
{
    if(!m_popupwidget->renderPopup(word, line))
    {
        this->hide();
        return;
    }

    QPoint pt = QCursor::pos();
    pt.rx() += POPUP_MARGIN;
    pt.ry() += POPUP_MARGIN;

    this->move(pt);
    this->show();
    this->updateGeometry();
}

void DisassemblerPopup::mouseMoveEvent(QMouseEvent* e)
{
    if(m_lastpos != e->globalPos()) // WHEEL -> MOVE ?!?
        this->hide();

    QWidget::mouseMoveEvent(e);
}

void DisassemblerPopup::wheelEvent(QWheelEvent* e)
{
    m_lastpos = e->globalPos();
    QPoint delta = e->angleDelta();

    if(delta.y() > 0)
        m_popupwidget->lessRows();
    else
        m_popupwidget->moreRows();

    this->updateGeometry();
    QWidget::wheelEvent(e);
}

void DisassemblerPopup::updateGeometry()
{
    this->setFixedWidth(m_documentrenderer->maxWidth());
    this->setFixedHeight(m_popupwidget->rows() * std::ceil(m_documentrenderer->fontMetrics().height()));
}
