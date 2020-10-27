#pragma once

#include "qtrenderer.h"

class QPainter;

struct RDRendererItem;

class PainterRenderer: public QtRenderer
{
    Q_OBJECT

    public:
        PainterRenderer(const RDContextPtr& ctx, rd_flag flags = SurfaceFlags_Normal, QObject* parent = 0);
        void render(QPainter* painter, size_t first, size_t last);

    private:
        void render(const RDRendererItem* item, size_t index);

    private:
        QPainter* m_painter{nullptr};
};
