#include "disassemblerpopupview.h"
#include "../../redasmsettings.h"
#include <QGraphicsDropShadowEffect>
#include <QPainter>

DisassemblerPopupView::DisassemblerPopupView(const RDContextPtr& ctx, QWidget *parent): QWidget(parent), m_context(ctx)
{
    QPalette palette = this->palette();
    palette.setColor(QPalette::Base, palette.color(QPalette::ToolTipBase));
    this->setPalette(palette);
    this->setFont(REDasmSettings::font());
    this->setCursor(Qt::ArrowCursor);

    QGraphicsDropShadowEffect* dropshadow = new QGraphicsDropShadowEffect(this);
    dropshadow->setBlurRadius(5);
    this->setGraphicsEffect(dropshadow);

    m_surface = new SurfaceRenderer(ctx, RendererFlags_Simplified, this);
    connect(m_surface, &SurfaceRenderer::renderCompleted, this, [&]() { this->update(); });
}

bool DisassemblerPopupView::renderPopup(const RDSymbol* symbol)
{
    if(!m_surface->goToAddress(symbol->address)) return false;

    m_rows = POPUP_START_ROWS;
    this->renderPopup();
    return true;
}

void DisassemblerPopupView::moreRows()
{
    m_rows++;
    this->renderPopup();
}

void DisassemblerPopupView::lessRows()
{
    if(m_rows == 1) return;
    m_rows--;
    this->renderPopup();
}

void DisassemblerPopupView::renderPopup()
{
    m_surface->resize(m_rows, m_maxcols);
    m_maxcols = std::max(RDSurface_GetLastColumn(m_surface->handle()), m_maxcols);

    QSize sz = m_surface->size();
    this->setFixedSize(sz);

    // Resize and offset parent
    sz.rwidth() += POPUP_MARGIN;
    sz.rheight() += POPUP_MARGIN;
    this->parentWidget()->setFixedSize(sz);
}

void DisassemblerPopupView::paintEvent(QPaintEvent*)
{
    QPainter painter(this);
    painter.drawPixmap(QPoint(0, 0), m_surface->pixmap());
}
