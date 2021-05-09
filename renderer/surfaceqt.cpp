#include "surfaceqt.h"
#include "../hooks/disassemblerhooks.h"
#include "../themeprovider.h"
#include <QApplication>
#include <QClipboard>
#include <QPainter>
#include <QWidget>
#include <limits>

SurfaceQt::SurfaceQt(const RDContextPtr& ctx, rd_flag flags, QObject *parent) : QObject(parent), m_context(ctx)
{
    m_basecolor = this->widget()->palette().color(QPalette::Base);
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
            case Event_SurfaceHistoryChanged: Q_EMIT thethis->historyChanged(); break;

            case Event_SurfaceAddressChanged: {
                DisassemblerHooks::instance()->statusAddress(thethis);
                Q_EMIT thethis->addressChanged();
                break;
            }

            default: break;
        }
    }, nullptr);
}

SurfaceQt::~SurfaceQt() { RDObject_Unsubscribe(m_surface.get(), this); }

void SurfaceQt::renderRange(QPainter* painter, rd_address startaddress, rd_address endaddress)
{
    int firstrow = (startaddress == RD_NVAL) ? this->indexOf(RDSurface_GetFirstAddress(m_surface.get()))
                                             : this->indexOf(startaddress);

    int lastrow = (endaddress == RD_NVAL) ? this->lastIndexOf(RDSurface_GetLastAddress(m_surface.get()))
                                          : this->lastIndexOf(endaddress);

    if((firstrow == -1) || (lastrow == -1))
        return;

    painter->setBackgroundMode(Qt::OpaqueMode);
    painter->setFont(this->widget()->font());

    const RDSurfaceCell* cells = nullptr;
    QPointF pt(0, 0);

    for(int i = firstrow; i <= lastrow; i++, pt.ry() += this->cellHeight())
    {
        int maxcols = RDSurface_GetRow(this->handle(), i, &cells);
        pt.rx() = 0;

        for(int col = 0; col < maxcols; col++, pt.rx() += this->cellWidth())
        {
            auto& cell = cells[col];
            painter->setBackground(this->getBackground(&cell));
            painter->setPen(this->getForeground(&cell));
            painter->drawText({ pt, this->cellSize() }, Qt::TextSingleLine, QString(cell.ch));
        }
    }
}

bool SurfaceQt::contains(rd_address address) const { return RDSurface_Contains(m_surface.get(), address); }
int SurfaceQt::rows() const { return this->widget()->height() / m_cellsize.height(); }
int SurfaceQt::indexOf(rd_address address) const { return RDSurface_IndexOf(m_surface.get(), address); }
int SurfaceQt::lastIndexOf(rd_address address) const { return RDSurface_LastIndexOf(m_surface.get(), address); }

QSize SurfaceQt::rangeSize(rd_address startaddress, rd_address endaddress) const
{
    int idx = RDSurface_IndexOf(m_surface.get(), startaddress);
    int lastidx = RDSurface_LastIndexOf(m_surface.get(), endaddress);
    if((idx == -1) || (lastidx == -1)) return QSize();

    int maxcol = RDSurface_GetRangeColumn(m_surface.get(), startaddress, endaddress);

    return QSize(maxcol * m_cellsize.width(),
                 ((lastidx - idx) + 1) * m_cellsize.height());
}

QSize SurfaceQt::size() const
{
    int rows = 0, cols = 0;
    RDSurface_GetSize(m_surface.get(), &rows, &cols);
    return QSize(cols * m_cellsize.width(), rows * m_cellsize.height());
}

const QColor& SurfaceQt::baseColor() const { return m_basecolor; }
void SurfaceQt::setBaseColor(const QColor& c) { m_basecolor = c; }

void SurfaceQt::scroll(rd_address address, int ncols) { RDSurface_Scroll(m_surface.get(), address, ncols); }
bool SurfaceQt::goTo(rd_address address) { return RDSurface_GoTo(m_surface.get(), address); }
void SurfaceQt::getScrollRange(rd_address* start, rd_address* end) const { RDSurface_GetScrollRange(m_surface.get(), start, end); }
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

void SurfaceQt::resizeRange(rd_address startaddress, rd_address endaddress, int cols) { RDSurface_ResizeRange(m_surface.get(), startaddress, endaddress, cols); }
void SurfaceQt::resize(int row, int cols) { this->resize(QSizeF{ cols * m_cellsize.width(), row * m_cellsize.height() }); }
void SurfaceQt::resize() { this->resize(QSizeF{ static_cast<qreal>(this->widget()->width()), static_cast<qreal>(this->widget()->height()) }); }
void SurfaceQt::linkTo(SurfaceQt* s) { RDSurface_LinkTo(m_surface.get(), s->handle()); }
void SurfaceQt::unlink() { RDSurface_Unlink(m_surface.get()); }

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
rd_address SurfaceQt::firstAddress() const { return RDSurface_GetFirstAddress(m_surface.get()); }
rd_address SurfaceQt::lastAddress() const { return RDSurface_GetLastAddress(m_surface.get()); }
rd_address SurfaceQt::currentAddress() const { return RDSurface_GetCurrentAddress(m_surface.get()); }

void SurfaceQt::activateCursor(bool activate)
{
    if(activate) RDSurface_Activate(m_surface.get());
    else RDSurface_Deactivate(m_surface.get());
}

bool SurfaceQt::canGoBack() const { return RDSurface_CanGoBack(m_surface.get()); }
bool SurfaceQt::canGoForward() const { return RDSurface_CanGoForward(m_surface.get()); }
bool SurfaceQt::hasSelection() const { return RDSurface_HasSelection(m_surface.get()); }

QString SurfaceQt::getCurrentLabel(rd_address* address) const
{
    auto* s = RDSurface_GetCurrentLabel(m_surface.get(), address);
    return s ? QString::fromUtf8(s) : QString();
}

bool SurfaceQt::getLabelAt(const QPointF& pt, rd_address* address) const
{
    auto [row, col] = this->mapPoint(pt);
    return RDSurface_GetLabelAt(m_surface.get(), row, col, address);
}

const char* SurfaceQt::getCurrentWord() const { return RDSurface_GetCurrentWord(m_surface.get()); }
const RDSurfacePos* SurfaceQt::selection() const { return RDSurface_GetSelection(m_surface.get()); }
const RDSurfacePos* SurfaceQt::position() const { return RDSurface_GetPosition(m_surface.get()); }

QColor SurfaceQt::getBackground(const RDSurfaceCell* cell) const
{
    switch(cell->background)
    {
        case Theme_Default: return this->baseColor();
        case Theme_CursorBg: return qApp->palette().color(QPalette::WindowText);
        case Theme_SelectionBg: return qApp->palette().color(QPalette::Highlight);
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

bool SurfaceQt::seek(rd_address address) { return RDSurface_Seek(m_surface.get(), address); }
QFontMetricsF SurfaceQt::fontMetrics() const { return QFontMetricsF(this->widget()->font()); }
void SurfaceQt::render() { Q_EMIT renderCompleted(); }
QWidget* SurfaceQt::widget() const { return dynamic_cast<QWidget*>(this->parent()); }

void SurfaceQt::resize(const QSizeF& size)
{
    RDSurface_Resize(m_surface.get(),
                     size.height() / m_cellsize.height(),
                     size.width() / m_cellsize.width());
}
