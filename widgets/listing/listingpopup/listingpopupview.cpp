#include "listingpopupview.h"
#include "../../../redasmsettings.h"
#include <QGraphicsDropShadowEffect>
#include <QPainter>

ListingPopupView::ListingPopupView(const RDContextPtr& ctx, QWidget *parent): QWidget(parent), m_context(ctx)
{
    QPalette palette = this->palette();
    palette.setColor(QPalette::Base, palette.color(QPalette::ToolTipBase));
    this->setPalette(palette);
    this->setFont(REDasmSettings::font());
    this->setCursor(Qt::ArrowCursor);

    QGraphicsDropShadowEffect* dropshadow = new QGraphicsDropShadowEffect(this);
    dropshadow->setBlurRadius(5);
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
    sz.rwidth() += POPUP_MARGIN;
    sz.rheight() += POPUP_MARGIN;
    this->parentWidget()->setFixedSize(sz);
}

void ListingPopupView::paintEvent(QPaintEvent*)
{
    QPainter painter(this);
    painter.drawPixmap(QPoint(0, 0), m_surface->pixmap());
}
