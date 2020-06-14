#pragma once

#include "qtrenderer.h"

class QPainter;

class PainterRenderer: public QtRenderer
{
    public:
        PainterRenderer(RDDisassembler* disassembler, rd_flag flags = RendererFlags_Normal);
        void render(QPainter* painter, size_t first, size_t last);

    private:
        void render(const RDRendererItem* item, size_t index);

    private:
        QPainter* m_painter{nullptr};
};
