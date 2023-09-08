#include "listingpopup.h"
#include <QWheelEvent>
#include <QMouseEvent>
#include <QLayout>

ListingPopup::ListingPopup(const RDContextPtr& ctx, QWidget *parent): QWidget(parent), m_context(ctx)
{
    m_popupview = new ListingPopupView(ctx, this);

    QVBoxLayout* vboxlayout = new QVBoxLayout(this);
    vboxlayout->setContentsMargins(POPUP_MARGIN, POPUP_MARGIN, POPUP_MARGIN, POPUP_MARGIN);
    vboxlayout->addWidget(m_popupview);
    this->setLayout(vboxlayout);

    this->setAttribute(Qt::WA_TranslucentBackground);
    this->setWindowFlags(Qt::Popup);
    this->setMouseTracking(true);
    this->setMinimumHeight(0);
    this->setMinimumWidth(0);
}

void ListingPopup::popup(rd_address address)
{
    if(!m_popupview->renderPopup(address))
    {
        this->hide();
        return;
    }

    QPoint pt = QCursor::pos();
    pt.rx() += POPUP_MARGIN;
    pt.ry() += POPUP_MARGIN;

    this->move(pt);
    this->show();
}

void ListingPopup::mouseMoveEvent(QMouseEvent* event)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    if(m_lastpos != event->globalPosition())
#else
    if(m_lastpos != event->globalPos())
#endif
    {
        this->hide();
        event->accept();
    }
    else
        QWidget::mouseMoveEvent(event);
}

void ListingPopup::wheelEvent(QWheelEvent* event)
{
    m_lastpos = event->globalPosition();
    QPoint delta = event->angleDelta();

    if(delta.y() > 0) m_popupview->lessRows();
    else m_popupview->moreRows();
    event->accept();
}
