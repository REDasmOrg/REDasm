#include "graphmetrics.h"

int GraphMetrics::borderPadding() { return 3; }
int GraphMetrics::itemPadding() { return 25; }
int GraphMetrics::lineWidth() { return 2; }
float GraphMetrics::edgeOffsetBase() { return 6.0; }
float GraphMetrics::arrowSize() { return GraphMetrics::edgeOffsetBase() - 2.0; }
float GraphMetrics::angleSize() { return GraphMetrics::itemPadding() / 2; }
