#include "listingmaprenderer.h"
#include <QApplication>
#include <QPainter>
#include <QWidget>
#include <rdapi/graph/functiongraph.h>
#include "../../../themeprovider.h"

ListingMapRenderer::ListingMapRenderer(IDisassemblerCommand* command, QObject* parent): RendererAsync(parent), m_command(command)
{
    m_totalsize = RDBuffer_Size(RDDisassembler_GetBuffer(command->disassembler()));
}

void ListingMapRenderer::renderMap()
{
    m_renderenabled.store(true);
    this->schedule(ListingMapRenderer::LowPriority);
}

void ListingMapRenderer::onRender(QImage* image)
{
    m_renderenabled.store(false);
    this->checkOrientation();

    QPainter painter(image);
    painter.setPen(Qt::transparent);
    painter.fillRect(this->widget()->rect(), Qt::gray);

    this->renderSegments(&painter);
    if(!RD_IsBusy()) this->renderFunctions(&painter); // Don't render functions when disassembler is busy
    this->renderLabels(&painter);
    if(!RD_IsBusy()) this->renderSeek(&painter);      // Don't render seek when disassembler is busy
}

QRect ListingMapRenderer::buildRect(int p, int itemsize) const
{
    if(m_orientation == Qt::Horizontal) return QRect(p, 0, itemsize, this->widget()->height());
    return QRect(0, p, this->widget()->width(), itemsize);
}

int ListingMapRenderer::calculatePosition(rd_offset offset) const { return (offset * this->itemSize()) / m_totalsize; }
int ListingMapRenderer::calculateSize(u64 sz) const { return std::max<int>(1, (sz * this->itemSize()) / m_totalsize); }
int ListingMapRenderer::itemSize() const { return (m_orientation == Qt::Horizontal) ? this->widget()->width() : this->widget()->height(); }

bool ListingMapRenderer::checkOrientation()
{
    s32 oldorientation = m_orientation;
    m_orientation = (this->widget()->width() > this->widget()->height()) ? Qt::Horizontal : Qt::Vertical;
    return oldorientation != m_orientation;
}

void ListingMapRenderer::calculateSegments()
{
    RDDocument* doc = RDDisassembler_GetDocument(m_command->disassembler());
    size_t c = RDDocument_SegmentsCount(doc);
    m_calcsegments.clear();
    m_calcsegments.reserve(c);

    for(size_t i = 0; i < c; i++)
    {
        RDSegment segment;
        if(!RDDocument_GetSegmentAt(doc, i, &segment)) continue;
        if(HAS_FLAG(&segment, SegmentFlags_Bss)) continue;

        m_calcsegments.push_back({ segment, RDSegment_Size(&segment) });
    }
}

void ListingMapRenderer::calculateFunctions()
{
    RDDocument* doc = RDDisassembler_GetDocument(m_command->disassembler());
    size_t c = RDDocument_FunctionsCount(doc);
    m_calcfunctions.clear();
    m_calcfunctions.reserve(c);

    RDLoader* loader = RDDisassembler_GetLoader(m_command->disassembler());

    for(size_t i = 0; i < c; i++)
    {
        RDLocation loc = RDDocument_GetFunctionAt(doc, i);

        RDGraph* graph = nullptr;
        if(!RDDocument_GetFunctionGraph(doc, loc.address, &graph)) continue;

        const RDGraphNode* nodes = nullptr;
        size_t nc = RDGraph_GetNodes(graph, &nodes);

        for(size_t j = 0; j < nc; j++)
        {
            const RDFunctionBasicBlock* fbb = nullptr;
            if(!RDFunctionGraph_GetBasicBlock(graph, nodes[j], &fbb)) continue;

            RDDocumentItem item;
            if(!RDFunctionBasicBlock_GetStartItem(fbb, &item)) continue;

            RDLocation loc = RD_Offset(loader, item.address);
            if(!loc.valid) continue;

            m_calcfunctions.push_back({loc, RDFunctionBasicBlock_ItemsCount(fbb)});
        }
    }
}

bool ListingMapRenderer::conditionWait() const { return m_renderenabled.load(); }

void ListingMapRenderer::renderSegments(QPainter* painter)
{
    if(m_calcsegments.empty()) this->calculateSegments();

    for(const auto& [segment, size] : m_calcsegments)
    {
        QRect r = this->buildRect(this->calculatePosition(segment.offset), this->calculateSize(size));
        if(HAS_FLAG(&segment, SegmentFlags_Code)) painter->fillRect(r, THEME_VALUE(Theme_Symbol));
        else painter->fillRect(r, THEME_VALUE(Theme_Data));
    }
}

void ListingMapRenderer::renderFunctions(QPainter* painter)
{
    if(m_calcfunctions.empty()) this->calculateFunctions();

    size_t fsize = (m_orientation == Qt::Horizontal ? this->widget()->height() :
                                                      this->widget()->width()) / 2;

    for(const auto& [loc, c] : m_calcfunctions)
    {
        QRect r = this->buildRect(this->calculatePosition(loc.offset), this->calculateSize(c));
        if(m_orientation == Qt::Horizontal) r.setHeight(fsize);
        else r.setWidth(fsize);
        painter->fillRect(r, THEME_VALUE(Theme_Function));
    }
}

void ListingMapRenderer::renderSeek(QPainter* painter) const
{
    RDDocumentItem item;
    if(!m_command->getCurrentItem(&item)) return;

    RDLoader* loader = RDDisassembler_GetLoader(m_command->disassembler());
    RDLocation offset  = RD_Offset(loader, item.address);
    if(!offset.valid) return;

    QColor seekcolor = THEME_VALUE(Theme_Seek);
    seekcolor.setAlphaF(0.4);

    QRect r;
    if(m_orientation == Qt::Horizontal) r = QRect(this->calculatePosition(offset.value), 0, this->widget()->width() * 0.05, this->widget()->height());
    else r = QRect(0, this->calculatePosition(offset.value), this->widget()->width(), this->widget()->height() * 0.05);
    painter->fillRect(r, seekcolor);
}

void ListingMapRenderer::renderLabels(QPainter* painter)
{
    if(m_calcsegments.empty()) this->calculateSegments();

    QFontMetrics fm = painter->fontMetrics();
    painter->setPen(qApp->palette().color(QPalette::HighlightedText));

    for(const auto& [segment, size] : m_calcsegments)
    {
        if(HAS_FLAG(&segment, SegmentFlags_Bss)) continue;

        int pos = this->calculatePosition(segment.offset);
        int segmentsize = this->calculateSize(size);

        if(segmentsize < fm.height()) // Don't draw labels on small segments
            continue;

#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
        int w = fm.horizontalAdvance(" ") * 2;
#else
        int w = fm.width(" ") * 2;
#endif

        if(m_orientation == Qt::Horizontal)
        {
            painter->drawText(pos, 2, segmentsize - w, fm.height(),
                              Qt::AlignLeft | Qt::AlignBottom,
                              segment.name);
        }
        else
        {
            painter->drawText(2, pos, this->widget()->width() - w, fm.height(),
                              Qt::AlignRight | Qt::AlignTop,
                              segment.name);
        }
    }
}
