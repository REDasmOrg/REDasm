#include "listingmap.h"
#include "../../../themeprovider.h"
#include <rdapi/graph/functiongraph.h>
#include <QApplication>
#include <QPainter>
#include <algorithm>
#include <cassert>
#include <cmath>

#define LISTINGMAP_SIZE 64

ListingMap::ListingMap(QWidget *parent) : QWidget(parent)
{
    this->setBackgroundRole(QPalette::Base);
    this->setAutoFillBackground(true);

    RDEvent_Subscribe(this, [](const RDEventArgs* e, void* userdata) {
        auto* thethis = reinterpret_cast<ListingMap*>(userdata);
        if(RD_IsBusy() || !thethis->m_document) return;

        switch(e->eventid) {
            case Event_CursorPositionChanged:
            case Event_BusyChanged:
                thethis->update();
                break;

            default: break;
        }
    }, this);
}

ListingMap::~ListingMap() { RDEvent_Unsubscribe(this); }

void ListingMap::linkTo(IDisassemblerCommand* command)
{
    m_command = command;
    m_document = RDDisassembler_GetDocument(command->disassembler());
    m_totalsize = RDBuffer_Size(RDDisassembler_GetBuffer(command->disassembler()));
    this->update();
}

QSize ListingMap::sizeHint() const { return { LISTINGMAP_SIZE, LISTINGMAP_SIZE }; }
int ListingMap::calculateSize(u64 sz) const { return std::max<int>(1, (sz * this->itemSize()) / m_totalsize); }
int ListingMap::calculatePosition(offset_t offset) const { return (offset * this->itemSize()) / m_totalsize; }
int ListingMap::itemSize() const { return (m_orientation == Qt::Horizontal) ? this->width() : this->height(); }

QRect ListingMap::buildRect(int p, int itemsize) const
{
    if(m_orientation == Qt::Horizontal) return QRect(p, 0, itemsize, this->height());
    return QRect(0, p, this->width(), itemsize);
}

bool ListingMap::checkOrientation()
{
    s32 oldorientation = m_orientation;
    m_orientation = (this->width() > this->height()) ? Qt::Horizontal : Qt::Vertical;
    return oldorientation != m_orientation;
}

void ListingMap::drawLabels(QPainter* painter)
{
    QFontMetrics fm = painter->fontMetrics();
    painter->setPen(qApp->palette().color(QPalette::HighlightedText));

    for(size_t i = 0; i < RDDocument_SegmentsCount(m_document); i++)
    {
        RDSegment segment;
        assert(RDDocument_GetSegmentAt(m_document, i, &segment));
        if(HAS_FLAG(&segment, SegmentFlags_Bss)) continue;

        int pos = this->calculatePosition(segment.offset);
        int segmentsize = this->calculateSize(RDSegment_Size(&segment));

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
            painter->drawText(2, pos, this->width() - w, fm.height(),
                              Qt::AlignRight | Qt::AlignTop,
                              segment.name);
        }
    }
}

void ListingMap::renderSegments(QPainter* painter)
{
    for(size_t i = 0; i < RDDocument_SegmentsCount(m_document); i++)
    {
        RDSegment segment;
        assert(RDDocument_GetSegmentAt(m_document, i, &segment));
        if(HAS_FLAG(&segment, SegmentFlags_Bss)) continue;

        QRect r = this->buildRect(this->calculatePosition(segment.offset),
                                  this->calculateSize(RDSegment_Size(&segment)));

        if(HAS_FLAG(&segment, SegmentFlags_Code)) painter->fillRect(r, THEME_VALUE("label_fg"));
        else painter->fillRect(r, THEME_VALUE("data_fg"));
    }
}

void ListingMap::renderFunctions(QPainter *painter)
{
    size_t fsize = (m_orientation == Qt::Horizontal ? this->height() : this->width()) / 2;
    size_t c = RDDocument_FunctionsCount(m_document);
    RDLoader* loader = RDDisassembler_GetLoader(m_command->disassembler());

    for(size_t i = 0; i < c; i++)
    {
        RDLocation loc = RDDocument_GetFunctionAt(m_document, i);

        RDGraph* graph = nullptr;
        if(!RDDocument_GetFunctionGraph(m_document, loc.address, &graph)) continue;

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

            QRect r = this->buildRect(this->calculatePosition(loc.address), this->calculateSize(RDFunctionBasicBlock_ItemsCount(fbb)));
            if(m_orientation == Qt::Horizontal) r.setHeight(fsize);
            else r.setWidth(fsize);

            painter->fillRect(r, THEME_VALUE("function_fg"));
        }
    }
}

void ListingMap::renderSeek(QPainter *painter)
{
    RDDocumentItem item;
    if(!m_command->getCurrentItem(&item)) return;

    RDLoader* loader = RDDisassembler_GetLoader(m_command->disassembler());
    RDLocation offset  = RD_Offset(loader, item.address);
    if(!offset.valid) return;

    QColor seekcolor = THEME_VALUE("seek");
    seekcolor.setAlphaF(0.4);

    QRect r;
    if(m_orientation == Qt::Horizontal) r = QRect(this->calculatePosition(offset.value), 0, this->width() * 0.05, this->height());
    else r = QRect(0, this->calculatePosition(offset.value), this->width(), this->height() * 0.05);
    painter->fillRect(r, seekcolor);
}

void ListingMap::paintEvent(QPaintEvent *)
{
   if(!m_command) return;
   this->checkOrientation();

   QPainter painter(this);
   painter.setPen(Qt::transparent);
   painter.fillRect(this->rect(), Qt::gray);

   this->renderSegments(&painter);
   if(!RD_IsBusy())  this->renderFunctions(&painter); // Don't render functions when disassembler is busy
   this->drawLabels(&painter);
   if(!RD_IsBusy()) this->renderSeek(&painter);       // Don't render seek when disassembler is busy
}

void ListingMap::resizeEvent(QResizeEvent *e)
{
    QWidget::resizeEvent(e);
    this->update();
}
