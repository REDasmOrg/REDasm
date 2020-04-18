#include "listingmap.h"
#include "../themeprovider.h"
#include <QPainter>
#include <cassert>
#include <cmath>

#define LISTINGMAP_SIZE 32

ListingMap::ListingMap(QWidget *parent) : QWidget(parent)
{
    this->setBackgroundRole(QPalette::Base);
    this->setAutoFillBackground(true);
}

void ListingMap::setDisassembler(RDDisassembler* disassembler)
{
    m_disassembler = disassembler;
    m_document = RDDisassembler_GetDocument(disassembler);
    m_totalsize = RDBuffer_Size(RDDisassembler_GetBuffer(disassembler));
    this->update();

    // r_evt::subscribe(REDasm::StandardEvents::Cursor_PositionChanged, this, [=](const REDasm::EventArgs*) {
    //     if(r_disasm->busy()) return;
    //     QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
    // });

    // r_evt::subscribe(REDasm::StandardEvents::Disassembler_BusyChanged, this, [=](const REDasm::EventArgs*) {
    //     if(!r_disasm->busy()) QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
    // });
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
    QPalette palette = this->palette();
    QFontMetrics fm = painter->fontMetrics();

    painter->setPen(palette.color(QPalette::HighlightedText));

    for(size_t i = 0; i < RDDocument_SegmentsCount(m_document); i++)
    {
        RDSegment segment;
        assert(RDDocument_GetSegmentAt(m_document, i, &segment));
        if(segment.type & SegmentType_Bss) continue;

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
        if(segment.type & SegmentType_Bss) continue;

        QRect r = this->buildRect(this->calculatePosition(segment.offset),
                                  this->calculateSize(RDSegment_Size(&segment)));

        if(segment.type & SegmentType_Code) painter->fillRect(r, THEME_VALUE("label_fg"));
        else painter->fillRect(r, THEME_VALUE("data_fg"));
    }
}

void ListingMap::renderFunctions(QPainter *painter)
{
//    auto lock = REDasm::s_lock_safe_ptr(r_doc);
//    size_t fsize = (m_orientation == Qt::Horizontal ? this->height() : this->width()) / 2;
//
//    for(size_t i = 0; i < lock->functionsCount(); i++)
//    {
//        address_t address = lock->functionAt(i);
//        const REDasm::Symbol* symbol = lock->symbol(address);
//        const REDasm::FunctionGraph* g = lock->graph(address);
//        if(!g) continue;
//
//        g->nodes().each([&](REDasm::Node n) {
//            const REDasm::FunctionBasicBlock* fbb = variant_object<REDasm::FunctionBasicBlock>(g->data(n));
//            if(!fbb) return;
//
//            REDasm::ListingItem startitem = fbb->startItem();
//            QRect r = this->buildRect(this->calculatePosition(r_ldr->offset(startitem.address)), this->calculateSize(fbb->count()));
//
//            if(m_orientation == Qt::Horizontal) r.setHeight(fsize);
//            else r.setWidth(fsize);
//
//            painter->fillRect(r, THEME_VALUE("function_fg"));
//        });
//    }
}

void ListingMap::renderSeek(QPainter *painter)
{
//    REDasm::ListingItem item = r_doc->currentItem();
//    if(!item.isValid()) return;
//
//    offset_location offset  = r_ldr->offset(item.address);
//    if(!offset.valid) return;
//
//    QColor seekcolor = THEME_VALUE("seek");
//    seekcolor.setAlphaF(0.4);
//
//    QRect r;
//
//    if(m_orientation == Qt::Horizontal)
//       r = QRect(this->calculatePosition(offset), 0, this->width() * 0.05, this->height());
//    else
//       r = QRect(0, this->calculatePosition(offset), this->width(), this->height() * 0.05);
//
//    painter->fillRect(r, seekcolor);
}

void ListingMap::paintEvent(QPaintEvent *)
{
   if(!m_disassembler) return;
   this->checkOrientation();

   QPainter painter(this);
   painter.setPen(Qt::transparent);
   painter.fillRect(this->rect(), Qt::gray);

   this->renderSegments(&painter);

   // if(!r_disasm->busy()) // Don't render functions when disassembler is busy
   //     this->renderFunctions(&painter);

   this->drawLabels(&painter);

   // if(!r_disasm->busy()) // Don't render seek when disassembler is busy
   //     this->renderSeek(&painter);
}

void ListingMap::resizeEvent(QResizeEvent *e)
{
    QWidget::resizeEvent(e);
    this->update();
}
