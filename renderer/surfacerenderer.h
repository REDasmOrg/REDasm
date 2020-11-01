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
        explicit SurfaceRenderer(const RDContextPtr& ctx, rd_flag flags, QObject *parent = nullptr);
        const QPixmap& pixmap() const;
        RDSurface* handle() const;
        RDSurfacePos mapPoint(const QPointF& pt) const;
        const QColor& baseColor() const;
        QSize size() const;
        int rows() const;
        void setBaseColor(const QColor& c);
        void scroll(int nrows, int ncols);
        bool goToAddress(rd_address address);
        void moveTo(int row, int col);
        void moveTo(const QPointF& pt);
        void select(int row, int col);
        void select(const QPointF& pt);
        void resize(int row, int cols);
        void resize();

    private:
        void resize(const QSizeF& size);
        QWidget* owner() const;
        QFontMetricsF fontMetrics() const;
        void applyBackground(QPainter* painter, const RDSurfaceCell& cell) const;
        void applyForeground(QPainter* painter, const RDSurfaceCell& cell) const;
        void render();

    signals:
        void renderCompleted();

    private:
        QColor m_basecolor;
        rd_ptr<RDSurface> m_surface;
        RDContextPtr m_context;
        QSizeF m_cellsize;
        QPixmap m_pixmap;
        QImage m_image;
};

