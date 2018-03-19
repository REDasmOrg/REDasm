#ifndef GRAPHVIEWMETRICS_H
#define GRAPHVIEWMETRICS_H

#include "../../redasm/graph/graph.h"

class GraphViewMetrics
{
    public:
        static int borderPadding();
        static int itemPadding();
        static int lineWidth();
        static float edgeOffsetBase();
        static float arrowSize();
        static float angleSize();

    public:
        static float minimumWidth(const REDasm::Graphing::Vertex* v);
};

#endif // GRAPHVIEWMETRICS_H
