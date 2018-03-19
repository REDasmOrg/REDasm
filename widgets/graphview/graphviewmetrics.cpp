#include "graphviewmetrics.h"

int GraphViewMetrics::borderPadding()
{
    return 3;
}

int GraphViewMetrics::itemPadding()
{
    return 25;
}

int GraphViewMetrics::lineWidth()
{
    return 2;
}

float GraphViewMetrics::edgeOffsetBase()
{
    return 6.0;
}

float GraphViewMetrics::arrowSize()
{
    return GraphViewMetrics::edgeOffsetBase() - 2.0;
}

float GraphViewMetrics::angleSize()
{
    return GraphViewMetrics::itemPadding() / 2;
}

float GraphViewMetrics::minimumWidth(const REDasm::Graphing::Vertex *v)
{
    REDasm::Graphing::VertexSet parents = v->graph->getParents(v);
    return (std::max(parents.size(), v->edges.size()) + 2) * GraphViewMetrics::edgeOffsetBase();
}
