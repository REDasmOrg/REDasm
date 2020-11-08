#include "surfaceqt.h"
#include "../hooks/disassemblerhooks.h"
#include "../themeprovider.h"
#include <QApplication>
#include <QClipboard>
#include <QWidget>

SurfaceQt::SurfaceQt(const RDContextPtr& ctx, rd_flag flags, QObject *parent) : QObject(parent), m_context(ctx)
{
    m_basecolor = this->owner()->palette().color(QPalette::Base);
    m_surface = rd_ptr<RDSurface>(RDSurface_Create(ctx.get(), flags, reinterpret_cast<uintptr_t>(this)));

    QFontMetricsF fm = this->fontMetrics();
    m_cellsize.rheight() = fm.height();

#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    m_cellsize.rwidth() = fm.horizontalAdvance(" ");
#else
    m_cellsize.rwidth() = fm.width(" ");
#endif

    RDObject_Subscribe(m_surface.get(), this, [](const RDEventArgs* event) {
        auto* thethis = reinterpret_cast<SurfaceQt*>(event->owner);

        switch(event->id) {
            case Event_SurfaceUpdated: thethis->render(); break;

            case Event_SurfacePositionChanged: {
                auto* hooks = DisassemblerHooks::instance();
                hooks->statusAddress(dynamic_cast<const ICommand*>(thethis->owner()));
                emit thethis->positionChanged();
                break;
            }

            default: break;
        }
    }, nullptr);
}

SurfaceQt::~SurfaceQt() { RDObject_Unsubscribe(m_surface.get(), this); }
int SurfaceQt::rows() const { return this->owner()->height() / m_cellsize.height(); }

QSize SurfaceQt::size() const
{
    int rows = 0, cols = 0;
    RDSurface_GetSize(m_surface.get(), &rows, &cols);
    return QSize(cols * m_cellsize.width(), rows * m_cellsize.height());
}

const QColor& SurfaceQt::baseColor() const { return m_basecolor; }
void SurfaceQt::setBaseColor(const QColor& c) { m_basecolor = c; }

void SurfaceQt::scroll(int nrows, int ncols) { RDSurface_Scroll(m_surface.get(), nrows, ncols); }
bool SurfaceQt::goTo(const RDDocumentItem* item) { return RDSurface_GoTo(m_surface.get(), item);     }
bool SurfaceQt::goToAddress(rd_address address) { return RDSurface_GoToAddress(m_surface.get(), address); }
void SurfaceQt::goBack() { RDSurface_GoBack(m_surface.get()); }
void SurfaceQt::goForward() { RDSurface_GoForward(m_surface.get()); }
void SurfaceQt::moveTo(int row, int col) { RDSurface_MoveTo(m_surface.get(), row, col); }

void SurfaceQt::moveTo(const QPointF& pt)
{
    RDSurface_MoveTo(m_surface.get(),
                     pt.y() / m_cellsize.height(),
                     pt.x() / m_cellsize.width());
}

void SurfaceQt::select(int row, int col) { RDSurface_Select(m_surface.get(), row, col); }

void SurfaceQt::select(const QPointF& pt)
{
    RDSurface_Select(m_surface.get(),
                     pt.y() / m_cellsize.height(),
                     pt.x() / m_cellsize.width());
}

void SurfaceQt::selectAt(const QPointF& pt)
{
    RDSurface_SelectAt(m_surface.get(),
                       pt.y() / m_cellsize.height(),
                       pt.x() / m_cellsize.width());
}

void SurfaceQt::resize(int row, int cols) { this->resize(QSizeF{ cols * m_cellsize.width(), row * m_cellsize.height() }); }
void SurfaceQt::resize() { this->resize(QSizeF{ static_cast<qreal>(this->owner()->width()), static_cast<qreal>(this->owner()->height()) }); }

void SurfaceQt::copy() const
{
    QString s = RDSurface_GetSelectedText(m_surface.get());
    if(!s.isEmpty()) qApp->clipboard()->setText(s);
}

const QSizeF& SurfaceQt::cellSize() const { return m_cellsize; }
qreal SurfaceQt::cellWidth() const { return m_cellsize.width(); }
qreal SurfaceQt::cellHeight() const { return m_cellsize.height(); }
const RDContextPtr& SurfaceQt::context() const { return m_context; }
RDSurface* SurfaceQt::handle() const { return m_surface.get(); }

void SurfaceQt::activateCursor(bool activate)
{
    if(activate) RDSurface_Activate(m_surface.get());
    else RDSurface_Deactivate(m_surface.get());
}

bool SurfaceQt::canGoBack() const { return RDSurface_CanGoBack(m_surface.get()); }
bool SurfaceQt::canGoForward() const { return RDSurface_CanGoForward(m_surface.get()); }
bool SurfaceQt::hasSelection() const { return RDSurface_HasSelection(m_surface.get()); }
bool SurfaceQt::getCurrentItem(RDDocumentItem* item) const { return RDSurface_GetCurrentItem(m_surface.get(), item); }
bool SurfaceQt::getCurrentSymbol(RDSymbol* symbol) const { return RDSurface_GetCurrentSymbol(m_surface.get(), symbol); }

bool SurfaceQt::getSymbolAt(const QPointF& pt, RDSymbol* symbol) const
{
    auto [row, col] = this->mapPoint(pt);
    return RDSurface_GetSymbolAt(m_surface.get(), row, col, symbol);
}

const char* SurfaceQt::getCurrentWord() const { return RDSurface_GetCurrentWord(m_surface.get()); }
const RDSurfacePos* SurfaceQt::selection() const { return RDSurface_GetSelection(m_surface.get()); }
const RDSurfacePos* SurfaceQt::position() const { return RDSurface_GetPosition(m_surface.get()); }

QColor SurfaceQt::getBackground(const RDSurfaceCell* cell) const
{
    switch(cell->background)
    {
        case Theme_Default: return this->baseColor();
        case Theme_CursorBg: return this->owner()->palette().color(QPalette::WindowText);
        case Theme_SelectionBg: return this->owner()->palette().color(QPalette::Highlight);
        default: break;
    }

    return THEME_VALUE(cell->background);
}

QColor SurfaceQt::getForeground(const RDSurfaceCell* cell) const
{
    switch(cell->foreground)
    {
        case Theme_Default: return qApp->palette().color(QPalette::WindowText);

        case Theme_CursorFg:
        case Theme_SelectionFg: return qApp->palette().color(QPalette::HighlightedText);
        default: break;
    }

    return THEME_VALUE(cell->foreground);
}

RDSurfacePos SurfaceQt::mapPoint(const QPointF& pt) const
{
    return { static_cast<int>(pt.y() / m_cellsize.height()),
                static_cast<int>(pt.x() / m_cellsize.width()) };
}

QFontMetricsF SurfaceQt::fontMetrics() const { return QFontMetricsF(this->owner()->font()); }
QWidget* SurfaceQt::owner() const { return dynamic_cast<QWidget*>(this->parent()); }

void SurfaceQt::resize(const QSizeF& size)
{
    RDSurface_Resize(m_surface.get(),
                     size.height() / m_cellsize.height(),
                     size.width() / m_cellsize.width());
}
