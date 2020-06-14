#pragma once

#include "rendererasync.h"
#include "painterrenderer.h"
#include <rdapi/rdapi.h>

class PainterRendererAsync: public RendererAsync, public PainterRenderer
{
    Q_OBJECT

    private:

    public:
        PainterRendererAsync(RDDisassembler* disassembler, rd_flag flags = RendererFlags_Normal, QObject* parent = nullptr);
        virtual ~PainterRendererAsync() = default;
        void scheduleImage(size_t first, size_t last);

    protected:
        bool conditionWait() const override;
        void onRender(QImage* image) override;

    private:
        size_t m_first{RD_NPOS}, m_last{RD_NPOS};
};

