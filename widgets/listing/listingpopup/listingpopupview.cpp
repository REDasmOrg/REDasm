#include "listingpopupview.h"
#include "../../../redasmsettings.h"
#include "listingpopupshadow.h"
#include <QPainter>

ListingPopupView::ListingPopupView(const RDContextPtr& ctx, QWidget *parent): QWidget(parent), m_context(ctx)
{
    this->setFont(REDasmSettings::font());
    this->setCursor(Qt::ArrowCursor);
    this->setAutoFillBackground(true);

    auto* dropshadow = new ListingPopupShadow(this);
    dropshadow->setBlurRadius(20.0);
    dropshadow->setDistance(6.0);
    dropshadow->setColor(QColor(0, 0, 0, 80));
    this->setGraphicsEffect(dropshadow);

    m_surface = new SurfacePainter(ctx, RendererFlags_Simplified, this);
    connect(m_surface, &SurfacePainter::renderCompleted, this, [&]() { this->update(); });
}

bool ListingPopupView::renderPopup(const RDSymbol* symbol)
{
    if(!m_surface->goToAddress(symbol->address)) return false;

    m_rows = POPUP_START_ROWS;
    this->renderPopup();
    return true;
}

void ListingPopupView::moreRows()
{
    m_rows++;
    this->renderPopup();
}

void ListingPopupView::lessRows()
{
    if(m_rows == 1) return;
    m_rows--;
    this->renderPopup();
}

void ListingPopupView::renderPopup()
{
    m_surface->resize(m_rows, -1);
    RDSurface_GetSize(m_surface->handle(), nullptr, &m_maxcols);

    QSize sz = m_surface->size();
    this->setFixedSize(sz);

    // Resize and offset parent
    sz.rwidth() += POPUP_MARGIN * 2;
    sz.rheight() += POPUP_MARGIN * 2;
    this->parentWidget()->setFixedSize(sz);
}

void ListingPopupView::paintEvent(QPaintEvent*)
{
    QPainter painter(this);
    painter.drawPixmap(QPoint(0, 0), m_surface->pixmap());
}
