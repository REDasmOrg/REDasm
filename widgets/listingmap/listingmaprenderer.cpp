#include "listingmaprenderer.h"
#include <QApplication>
#include <QPainter>
#include <QWidget>
#include <rdapi/graph/functiongraph.h>
#include "../../renderer/surfaceqt.h"
#include "../../themeprovider.h"

ListingMapRenderer::ListingMapRenderer(const RDContextPtr& ctx, QObject* parent): RendererAsync(ctx, parent)
{
    m_totalsize = RDBuffer_Size(RDContext_GetBuffer(ctx.get()));
    m_document = RDContext_GetDocument(m_context.get());
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
    if(!RDContext_IsBusy(m_context.get())) this->renderFunctions(&painter); // Don't render functions when disassembler is busy
    this->renderLabels(&painter);
    if(!RDContext_IsBusy(m_context.get())) this->renderSeek(&painter);      // Don't render seek when disassembler is busy
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
    m_calcsegments.clear();

    RDDocument_EachSegment(m_document, [](const RDSegment* segment, void* userdata) {
        auto* thethis = reinterpret_cast<ListingMapRenderer*>(userdata);

        if(!HAS_FLAG(segment, SegmentFlags_Bss))
            thethis->m_calcsegments.push_back({ *segment, RDSegment_Size(segment) });

        return true;
    }, this);
}

void ListingMapRenderer::calculateFunctions()
{
    m_calcfunctions.clear();

    RDDocument_EachFunction(m_document, [](rd_address address, void* userdata) {
        auto* thethis = reinterpret_cast<ListingMapRenderer*>(userdata);
        if(thethis->aborted()) return false;

        RDGraph* graph = nullptr;
        if(!RDDocument_GetFunctionGraph(thethis->m_document, address, &graph)) return true;

        const RDGraphNode* nodes = nullptr;
        size_t c = RDGraph_GetNodes(graph, &nodes);

        for(size_t i = 0; i < c; i++) {
            const RDFunctionBasicBlock* fbb = nullptr;
            if(!RDFunctionGraph_GetBasicBlock(graph, nodes[i], &fbb)) continue;

            RDDocumentItem item;
            if(!RDFunctionBasicBlock_GetStartItem(fbb, &item)) continue;

            RDLocation loc = RD_Offset(thethis->m_context.get(), item.address);
            if(loc.valid) thethis->m_calcfunctions.push_back({loc, RDFunctionBasicBlock_ItemsCount(fbb)});
        }
        return true;
    }, this);
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
    if(this->aborted()) return;

    size_t fsize = (m_orientation == Qt::Horizontal ? this->widget()->height() :
                                                      this->widget()->width()) / 2;

    for(const auto& [loc, c] : m_calcfunctions)
    {
        if(this->aborted()) break;

        QRect r = this->buildRect(this->calculatePosition(loc.offset), this->calculateSize(c));
        if(m_orientation == Qt::Horizontal) r.setHeight(fsize);
        else r.setWidth(fsize);
        painter->fillRect(r, THEME_VALUE(Theme_Function));
    }
}

void ListingMapRenderer::renderSeek(QPainter* painter) const
{
    auto* activesurface = RDContext_GetActiveSurface(m_context.get());
    if(!activesurface) return;

    auto* surface = reinterpret_cast<const SurfaceQt*>(RDSurface_GetUserData(activesurface));
    if(!surface) return;

    RDDocumentItem item;
    if(!surface->getCurrentItem(&item)) return;

    RDLocation loc = RD_Offset(m_context.get(), item.address);
    if(!loc.valid) return;

    QColor seekcolor = THEME_VALUE(Theme_Seek);
    seekcolor.setAlphaF(0.4);

    QRect r;
    if(m_orientation == Qt::Horizontal) r = QRect(this->calculatePosition(loc.offset), 0, this->widget()->width() * 0.05, this->widget()->height());
    else r = QRect(0, this->calculatePosition(loc.offset), this->widget()->width(), this->widget()->height() * 0.05);
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
