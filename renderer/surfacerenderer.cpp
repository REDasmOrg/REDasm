#include "surfacerenderer.h"
#include "../hooks/disassemblerhooks.h"
#include "../hooks/icommand.h"
#include "../themeprovider.h"
#include <QAbstractScrollArea>
#include <QApplication>
#include <QPainter>
#include <QWidget>
#include <cmath>

SurfaceRenderer::SurfaceRenderer(const RDContextPtr& ctx, rd_flag flags, QObject* parent): QObject(parent), m_context(ctx)
{
    m_basecolor = this->owner()->palette().color(QPalette::Base);
    m_surface = rd_ptr<RDSurface>(RDSurface_Create(ctx.get(), flags));

    QFontMetricsF fm = this->fontMetrics();
    m_cellsize.rheight() = fm.height();

#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    m_cellsize.rwidth() = fm.horizontalAdvance(" ");
#else
    m_cellsize.rwidth() = fm.width(" ");
#endif

    RDObject_Subscribe(m_surface.get(), this, [](const RDEventArgs* event) {
        auto* thethis = reinterpret_cast<SurfaceRenderer*>(event->owner);

        switch(event->eventid) {
            case Event_SurfaceUpdated: thethis->render(); break;

            case Event_SurfaceChanged: {
                auto* hooks = DisassemblerHooks::instance();
                hooks->statusAddress(dynamic_cast<const ICommand*>(thethis->owner()));
                break;
            }

            default: break;
        }
    }, nullptr);
}

const QPixmap& SurfaceRenderer::pixmap() const { return m_pixmap; }
RDSurface* SurfaceRenderer::handle() const { return m_surface.get(); }

RDSurfacePos SurfaceRenderer::mapPoint(const QPointF& pt) const
{
    return { static_cast<int>(pt.y() / m_cellsize.height()),
                static_cast<int>(pt.x() / m_cellsize.width()) };
}

const QColor& SurfaceRenderer::baseColor() const { return m_basecolor; }

QSize SurfaceRenderer::size() const
{
    int rows = 0, cols = 0;
    RDSurface_GetSize(m_surface.get(), &rows, &cols);
    return QSize(cols * m_cellsize.width(), rows * m_cellsize.height());
}

int SurfaceRenderer::rows() const { return this->owner()->height() / m_cellsize.height(); }
void SurfaceRenderer::setBaseColor(const QColor& c) { m_basecolor = c; }
QWidget* SurfaceRenderer::owner() const { return dynamic_cast<QWidget*>(this->parent()); }
QFontMetricsF SurfaceRenderer::fontMetrics() const { return QFontMetricsF(this->owner()->font()); }
void SurfaceRenderer::scroll(int nrows, int ncols) { RDSurface_Scroll(m_surface.get(), nrows, ncols); }
bool SurfaceRenderer::goToAddress(rd_address address) { return RDSurface_GoToAddress(m_surface.get(), address); }
void SurfaceRenderer::moveTo(int row, int col) { RDSurface_MoveTo(m_surface.get(), row, col); }

void SurfaceRenderer::moveTo(const QPointF& pt)
{
    RDSurface_MoveTo(m_surface.get(),
                     pt.y() / m_cellsize.height(),
                     pt.x() / m_cellsize.width());
}

void SurfaceRenderer::select(int row, int col) { RDSurface_Select(m_surface.get(), row, col);  }

void SurfaceRenderer::select(const QPointF& pt)
{
    RDSurface_Select(m_surface.get(),
                     pt.y() / m_cellsize.height(),
                     pt.x() / m_cellsize.width());
}

void SurfaceRenderer::resize(int row, int cols) { this->resize({ cols * m_cellsize.width(), row * m_cellsize.height() }); }
void SurfaceRenderer::resize() { this->resize({ static_cast<qreal>(this->owner()->width()), static_cast<qreal>(this->owner()->height()) }); }

void SurfaceRenderer::resize(const QSizeF& size)
{
    m_image = QImage(QSize(size.width(), size.height()), QImage::Format_RGB32);

    RDSurface_Resize(m_surface.get(),
                     size.height() / m_cellsize.height(),
                     size.width() / m_cellsize.width());
}

void SurfaceRenderer::applyBackground(QPainter* painter, const RDSurfaceCell& cell) const
{
    switch(cell.background)
    {
        case Theme_Default: painter->setBackground(m_basecolor); break;
        case Theme_CursorBg: painter->setBackground(this->owner()->palette().brush(QPalette::WindowText)); break;
        case Theme_SelectionBg: painter->setBackground(this->owner()->palette().brush(QPalette::Highlight)); break;
        default: painter->setBackground(THEME_VALUE(cell.background)); break;
    }
}

void SurfaceRenderer::applyForeground(QPainter* painter, const RDSurfaceCell& cell) const
{
    if(cell.foreground == Theme_Default)
    {
        painter->setPen(qApp->palette().color(QPalette::WindowText));
        return;
    }

    switch(cell.foreground)
    {
        case Theme_CursorFg:
        case Theme_SelectionFg: painter->setPen(qApp->palette().color(QPalette::HighlightedText)); break;
        default: painter->setPen(THEME_VALUE(cell.foreground)); break;
    }
}

void SurfaceRenderer::render()
{
    QPainter painter(&m_image);
    painter.setBackgroundMode(Qt::OpaqueMode);
    painter.setFont(this->owner()->font());
    QPointF pt(0, 0);

    m_image.fill(this->owner()->palette().color(QPalette::Base));

    int rows = 0, cols = 0;
    RDSurface_GetSize(m_surface.get(), &rows, &cols);

    std::vector<RDSurfaceCell> cells(cols);

    for(int i = 0; i < rows; i++, pt.ry() += m_cellsize.height())
    {
        int c = RDSurface_GetRow(m_surface.get(), i, cells.data());
        pt.rx() = 0;

        for(int j = 0; j < c; j++, pt.rx() += m_cellsize.width())
        {
            auto& cell = cells[j];
            this->applyBackground(&painter, cell);
            this->applyForeground(&painter, cell);
            painter.drawText({ pt, m_cellsize }, Qt::TextSingleLine, QString(cell.ch));
        }
    }

    m_pixmap = QPixmap::fromImage(m_image);
    if(this->owner()) emit renderCompleted();
}
