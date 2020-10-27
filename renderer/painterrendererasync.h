#pragma once

#include "rendererasync.h"
#include "painterrenderer.h"
#include <rdapi/rdapi.h>

class PainterRendererAsync: public RendererAsync
{
    Q_OBJECT

    public:
        PainterRendererAsync(const RDContextPtr& disassembler, rd_flag flags = SurfaceFlags_Normal, QObject* parent = nullptr);
        void scheduleImage(size_t first, size_t last);
        PainterRenderer* renderer() const;

    protected:
        bool conditionWait() const override;
        void onRender(QImage* image) override;

    private:
        size_t m_first{RD_NPOS}, m_last{RD_NPOS};
        PainterRenderer* m_painterrenderer;
};

