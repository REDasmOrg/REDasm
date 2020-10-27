#pragma once

#include <QObject>
#include <QPixmap>
#include <QImage>
#include <rdapi/rdapi.h>
#include "../hooks/icommand.h"

class QFontMetricsF;

class SurfaceRenderer : public QObject
{
    Q_OBJECT

    public:
        explicit SurfaceRenderer(const RDContextPtr& ctx, QObject *parent = nullptr);
        RDSurface* surface() const;
        const QPixmap& pixmap() const;
        int rows() const;
        void scroll(int nrows, int ncols);
        void moveTo(int row, int col);
        void moveTo(const QPointF& pt);
        void select(int row, int col);
        void select(const QPointF& pt);
        void resize();

    private:
        const QWidget* owner() const;
        QFontMetricsF fontMetrics() const;
        void applyBackground(QPainter* painter, const RDSurfaceCell& cell) const;
        void applyForeground(QPainter* painter, const RDSurfaceCell& cell) const;
        void render();

    signals:
        void renderCompleted();

    private:
        rd_ptr<RDSurface> m_surface;
        RDContextPtr m_context;
        QSizeF m_cellsize;
        QPixmap m_pixmap;
        QImage m_image;
};

