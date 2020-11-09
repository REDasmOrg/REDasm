#pragma once

#include "../renderer/rendererasync.h"
#include "../hooks/icommand.h"
#include <rdapi/rdapi.h>
#include <deque>

class ListingMapRenderer : public RendererAsync
{
    Q_OBJECT

    private:
        template<typename T1, typename T2> using PreCalc = std::deque<std::pair<T1, T2>>;

    public:
        ListingMapRenderer(const RDContextPtr& ctx, QObject* parent);
        void renderMap();
        void calculateSegments();
        void calculateFunctions();

    protected:
        bool conditionWait() const override;
        void onRender(QImage* image) override;

    private:
        QRect buildRect(int offset, int itemsize) const;
        int calculatePosition(rd_offset offset) const;
        int calculateSize(u64 sz) const;
        int itemSize() const;
        void renderSegments(QPainter* painter);
        void renderFunctions(QPainter* painter);
        void renderSeek(QPainter* painter) const;
        void renderLabels(QPainter* painter);
        bool checkOrientation();

    private:
        RDContextPtr m_context;
        RDDocument* m_document;
        RDLoader* m_loader;
        PreCalc<RDSegment, size_t> m_calcsegments;
        PreCalc<RDLocation, rd_address> m_calcfunctions;
        s32 m_orientation{Qt::Vertical};
        size_t m_totalsize{0};
        std::atomic_bool m_renderenabled{false};
};

