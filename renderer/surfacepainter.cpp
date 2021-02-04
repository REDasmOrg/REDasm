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
    painter.setBackgroundMode(Qt::OpaqueMode);
    painter.setFont(this->widget()->font());
    QPointF pt(0, 0);

    const RDSurfaceCell* cells = nullptr;

    for(int row = 0; row < rows; row++, pt.ry() += this->cellHeight())
    {
        int maxcols = RDSurface_GetRow(this->handle(), row, &cells);
        pt.rx() = 0;

        for(int col = 0; col < maxcols; col++, pt.rx() += this->cellWidth())
        {
            auto& cell = cells[col];
            painter.setBackground(this->getBackground(&cell));
            painter.setPen(this->getForeground(&cell));
            painter.drawText({ pt, this->cellSize() }, Qt::TextSingleLine, QString(cell.ch));
        }
    }

    m_pixmap = QPixmap::fromImage(m_image);
    if(this->widget()) Q_EMIT renderCompleted();
}
