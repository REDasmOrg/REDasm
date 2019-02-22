#include "listingmap.h"
#include "../themeprovider.h"
#include <redasm/plugins/format.h>
#include <QPainter>
#include <cmath>

#define LISTINGMAP_SIZE 64

ListingMap::ListingMap(QWidget *parent) : QWidget(parent), m_disassembler(NULL), m_totalsize(0), m_orientation(Qt::Vertical)
{
    this->setBackgroundRole(QPalette::Base);
    this->setAutoFillBackground(true);
}

void ListingMap::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    m_disassembler = disassembler;
    m_totalsize = disassembler->format()->buffer()->size();

    auto& document = m_disassembler->document();

    for(auto it = document->begin(); it != document->end(); it++)
        this->addItem(it->get());

    this->checkOrientation();
    this->update();

    EVENT_CONNECT(document, changed, this, std::bind(&ListingMap::onDocumentChanged, this, std::placeholders::_1));

    EVENT_CONNECT(m_disassembler, busyChanged, this, [=]() {
        if(m_disassembler->busy())
            return;

        QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
    });
}

QSize ListingMap::sizeHint() const { return { LISTINGMAP_SIZE, LISTINGMAP_SIZE }; }
int ListingMap::calculateSize(u64 sz) const { return std::max(1, static_cast<int>((sz * this->itemSize()) / m_totalsize)); }
int ListingMap::calculatePosition(offset_t offset) const { return (offset * this->itemSize()) / m_totalsize; }

int ListingMap::itemSize() const
{
    if(m_orientation == Qt::Horizontal)
        return this->width();

    return this->height();
}

QRect ListingMap::buildRect(int p, int itemsize) const
{
    if(m_orientation == Qt::Horizontal)
        return QRect(p, 0, itemsize, this->height());

    return QRect(0, p, this->width(), itemsize);
}

bool ListingMap::checkOrientation()
{
    s32 oldorientation = m_orientation;

    if(this->width() > this->height())
        m_orientation = Qt::Horizontal;
    else
        m_orientation = Qt::Vertical;

    return oldorientation != m_orientation;
}

void ListingMap::drawLabels(QPainter* painter)
{
    QPalette palette = this->palette();
    QFontMetrics fm = painter->fontMetrics();
    auto lock = REDasm::s_lock_safe_ptr(m_disassembler->document());

    painter->setPen(palette.color(QPalette::HighlightedText));

    for(size_t i = 0; i < lock->segmentsCount(); i++)
    {
        const REDasm::Segment* segment = lock->segmentAt(i);

        if(segment->is(REDasm::SegmentTypes::Bss))
            continue;

        int pos = this->calculatePosition(segment->offset);
        int segmentsize = this->calculateSize(segment->size());

        if(segmentsize < fm.height()) // Don't draw labels on small segments
            continue;

        if(m_orientation == Qt::Horizontal)
        {
            painter->drawText(pos, 2, segmentsize, fm.height(),
                              Qt::AlignLeft | Qt::AlignTop,
                              QString::fromStdString(segment->name));
        }
        else
        {
            painter->drawText(2, pos, this->width(), fm.height(),
                              Qt::AlignLeft | Qt::AlignTop,
                              QString::fromStdString(segment->name));
        }
    }
}

void ListingMap::addItem(const REDasm::ListingItem *item)
{
    if(item->is(REDasm::ListingItem::FunctionItem))
    {
        auto it = REDasm::Listing::insertionPoint(&m_functions, item);
        m_functions.insert(it, item);
    }
}

void ListingMap::removeItem(const REDasm::ListingItem *item)
{
    if(item->is(REDasm::ListingItem::FunctionItem))
    {
        int idx = REDasm::Listing::indexOf(&m_functions, item);
        m_functions.removeAt(idx);
    }
}

void ListingMap::renderSegments(QPainter* painter)
{
    auto lock = REDasm::s_lock_safe_ptr(m_disassembler->document());

    for(size_t i = 0; i < lock->segmentsCount(); i++)
    {
        const REDasm::Segment* segment = lock->segmentAt(i);

        if(segment->is(REDasm::SegmentTypes::Bss))
            continue;

        QRect r = this->buildRect(this->calculatePosition(segment->offset),
                                  this->calculateSize(segment->size()));

        if(segment->is(REDasm::SegmentTypes::Code))
            painter->fillRect(r, THEME_VALUE("label_fg"));
        else
            painter->fillRect(r, THEME_VALUE("data_fg"));
    }
}

void ListingMap::renderFunctions(QPainter *painter)
{
    const auto* format = m_disassembler->format();
    auto lock = REDasm::s_lock_safe_ptr(m_disassembler->document());
    u64 size = 0;

    for(int i = 0; i < m_functions.size(); i++)
    {
        const REDasm::ListingItem* item = m_functions[i];

        if(item == m_functions.last())
        {
            REDasm::Segment* segment = lock->segment(item->address);
            size = segment->endaddress - item->address;
        }
        else
            size = m_functions[i + 1]->address - item->address;

        REDasm::SymbolPtr symbol = lock->symbol(item->address);
        offset_location offset = format->offset(symbol->address);

        if(!offset.valid)
            continue;

        QRect r = this->buildRect(this->calculatePosition(offset), this->calculateSize(size));

        if(m_orientation = Qt::Vertical)
            r.setX(std::ceil(this->width() / 2));
        else
            r.setY(std::ceil(this->height() / 2));

        if(symbol->isLocked())
            painter->fillRect(r, THEME_VALUE("locked_fg"));
        else
            painter->fillRect(r, THEME_VALUE("function_fg"));
    }
}

void ListingMap::onDocumentChanged(const REDasm::ListingDocumentChanged *ldc)
{
    if(ldc->isInserted())
        this->addItem(ldc->item);
    else if(ldc->isRemoved())
        this->removeItem(ldc->item);
}

void ListingMap::paintEvent(QPaintEvent *)
{
    if(!m_disassembler)
        return;

    QPainter painter(this);
    painter.setPen(Qt::transparent);
    painter.fillRect(this->rect(), Qt::gray);

    this->renderSegments(&painter);

    if(!m_disassembler->busy()) // Don't render functions when disassembler is busy
        this->renderFunctions(&painter);

    this->drawLabels(&painter);
}

void ListingMap::resizeEvent(QResizeEvent *e)
{
    QWidget::resizeEvent(e);

    if(this->checkOrientation())
        this->update();
}
