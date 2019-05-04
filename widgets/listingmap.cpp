#include "listingmap.h"
#include "../themeprovider.h"
#include <redasm/graph/functiongraph.h>
#include <redasm/plugins/loader.h>
#include <QPainter>
#include <cmath>

#define LISTINGMAP_SIZE 64

ListingMap::ListingMap(QWidget *parent) : QWidget(parent), m_disassembler(nullptr), m_orientation(Qt::Vertical), m_totalsize(0), m_lastseek(0)
{
    this->setBackgroundRole(QPalette::Base);
    this->setAutoFillBackground(true);
}

void ListingMap::setDisassembler(const REDasm::DisassemblerPtr& disassembler)
{
    m_disassembler = disassembler;
    m_totalsize = disassembler->loader()->buffer()->size();

    auto& document = m_disassembler->document();
    this->update();

    EVENT_CONNECT(document->cursor(), positionChanged, this, [=]() {
        if(m_disassembler->busy())
            return;

        QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
    });

    EVENT_CONNECT(m_disassembler, busyChanged, this, [=]() {
        if(m_disassembler->busy())
            return;

        QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
    });
}

QSize ListingMap::sizeHint() const { return { LISTINGMAP_SIZE, LISTINGMAP_SIZE }; }
int ListingMap::calculateSize(u64 sz) const { return std::max(1, static_cast<int>((sz * this->itemSize()) / m_totalsize)); }
int ListingMap::calculatePosition(offset_t offset) const { return (offset * this->itemSize()) / m_totalsize; }
int ListingMap::itemSize() const { return (m_orientation == Qt::Horizontal) ? this->width() : this->height(); }

QRect ListingMap::buildRect(int p, int itemsize) const
{
    if(m_orientation == Qt::Horizontal)
        return QRect(p, 0, itemsize, this->height());

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
    auto lock = REDasm::s_lock_safe_ptr(m_disassembler->document());

    painter->setPen(palette.color(QPalette::HighlightedText));

    for(const REDasm::Segment& segment : lock->segments())
    {
        if(segment.is(REDasm::SegmentType::Bss))
            continue;

        int pos = this->calculatePosition(segment.offset);
        int segmentsize = this->calculateSize(segment.size());

        if(segmentsize < fm.height()) // Don't draw labels on small segments
            continue;

        if(m_orientation == Qt::Horizontal)
        {
            painter->drawText(pos, 2, segmentsize - (fm.width(' ') * 2), fm.height(),
                              Qt::AlignLeft | Qt::AlignBottom,
                              QString::fromStdString(segment.name));
        }
        else
        {
            painter->drawText(2, pos, this->width() - (fm.width(' ') * 2), fm.height(),
                              Qt::AlignRight | Qt::AlignTop,
                              QString::fromStdString(segment.name));
        }
    }
}

void ListingMap::renderSegments(QPainter* painter)
{
    auto lock = REDasm::s_lock_safe_ptr(m_disassembler->document());

    for(const REDasm::Segment& segment : lock->segments())
    {
        if(segment.is(REDasm::SegmentType::Bss))
            continue;

        QRect r = this->buildRect(this->calculatePosition(segment.offset),
                                  this->calculateSize(segment.size()));

        if(segment.is(REDasm::SegmentType::Code))
            painter->fillRect(r, THEME_VALUE("label_fg"));
        else
            painter->fillRect(r, THEME_VALUE("data_fg"));
    }
}

void ListingMap::renderFunctions(QPainter *painter)
{
    auto lock = REDasm::s_lock_safe_ptr(m_disassembler->document());
    u64 fsize = (m_orientation == Qt::Horizontal ? this->height() : this->width()) / 2;

    for(const REDasm::ListingItem* item : lock->functions())
    {
        const REDasm::Symbol* symbol = lock->symbol(item->address);
        const REDasm::Graphing::FunctionGraph* g = lock->functions().graph(item);

        if(!g)
            continue;

        for(const auto& n : g->nodes())
        {
            const REDasm::Graphing::FunctionBasicBlock* fbb = g->data(n);

            if(!fbb)
                continue;

            QRect r = this->buildRect(this->calculatePosition(fbb->startidx), this->calculateSize(fbb->count()));

            if(m_orientation == Qt::Horizontal)
                r.setHeight(fsize);
            else
                r.setWidth(fsize);

            if(symbol->isLocked())
                painter->fillRect(r, THEME_VALUE("locked_fg"));
            else
                painter->fillRect(r, THEME_VALUE("function_fg"));
        }
    }
}

void ListingMap::renderSeek(QPainter *painter)
{
    const REDasm::ListingItem* item = m_disassembler->document()->currentItem();

    if(!item)
        return;

    offset_location offset  = m_disassembler->loader()->offset(item->address);

    if(!offset.valid)
        return;

    QColor seekcolor = THEME_VALUE("seek");
    seekcolor.setAlphaF(0.4);

    QRect r;

    if(m_orientation == Qt::Horizontal)
       r = QRect(this->calculatePosition(offset), 0, this->width() * 0.05, this->height());
    else
       r = QRect(0, this->calculatePosition(offset), this->width(), this->height() * 0.05);

    painter->fillRect(r, seekcolor);
}

void ListingMap::paintEvent(QPaintEvent *)
{
    if(!m_disassembler)
        return;

    this->checkOrientation();

    QPainter painter(this);
    painter.setPen(Qt::transparent);
    painter.fillRect(this->rect(), Qt::gray);

    this->renderSegments(&painter);

    if(!m_disassembler->busy()) // Don't render functions when disassembler is busy
        this->renderFunctions(&painter);

    this->drawLabels(&painter);

    if(!m_disassembler->busy()) // Don't render seek when disassembler is busy
        this->renderSeek(&painter);
}

void ListingMap::resizeEvent(QResizeEvent *e)
{
    QWidget::resizeEvent(e);
    this->update();
}
