#include "surfacepainter.h"
#include "../hooks/disassemblerhooks.h"
#include "../hooks/isurface.h"
#include "../themeprovider.h"
#include <QAbstractScrollArea>
#include <QApplication>
#include <QClipboard>
#include <QPainter>
#include <QWidget>
#include <cmath>

SurfacePainter::SurfacePainter(const RDContextPtr& ctx, rd_flag flags, QObject* parent): SurfaceQt(ctx, flags, parent) { }
const QPixmap& SurfacePainter::pixmap() const { return m_pixmap; }

void SurfacePainter::render()
{
    int rows = 0, cols = 0;
    RDSurface_GetSize(this->handle(), &rows, &cols);

    m_image = QImage(QSize(cols * this->cellWidth(), rows * this->cellHeight()), QImage::Format_RGB32);
    m_image.fill(this->widget()->palette().color(QPalette::Base));

    QPainter painter(&m_image);
    this->renderRange(&painter, RD_NVAL, rows);
    m_pixmap = QPixmap::fromImage(m_image);
    if(this->widget()) SurfaceQt::render();
}
