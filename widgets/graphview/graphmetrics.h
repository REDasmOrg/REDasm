#ifndef GRAPHMETRICS_H
#define GRAPHMETRICS_H

class GraphMetrics
{
    public:
        GraphMetrics() = delete;
        GraphMetrics(const GraphMetrics&) = delete;

    public:
        static int borderPadding();
        static int itemPadding();
        static int lineWidth();
        static float edgeOffsetBase();
        static float arrowSize();
        static float angleSize();
};

#endif // GRAPHMETRICS_H
