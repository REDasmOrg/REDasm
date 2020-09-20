#pragma once

#include "qtrenderer.h"

class QPainter;

class PainterRenderer: public QtRenderer
{
    Q_OBJECT

    public:
        PainterRenderer(const RDDisassemblerPtr& disassembler, rd_flag flags = RendererFlags_Normal, QObject* parent = 0);
        void render(QPainter* painter, size_t first, size_t last);

    private:
        void render(const RDRendererItem* item, size_t index);

    private:
        QPainter* m_painter{nullptr};
};
