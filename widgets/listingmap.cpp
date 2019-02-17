#include "listingmap.h"
#include "../themeprovider.h"
#include <QPainter>
#include <cmath>

ListingMap::ListingMap(QWidget *parent) : QWidget(parent), m_disassembler(NULL), m_totalsize(0), m_orientation(Qt::Vertical) { }

void ListingMap::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    m_disassembler = disassembler;

    m_totalsize = disassembler->document()->segmentsCount() +
                  disassembler->document()->functionsCount();

    auto& document = m_disassembler->document();

    for(auto it = document->begin(); it != document->end(); it++)
        this->addItem(it->get());

    this->checkOrientation();
    this->update();

    document->changed += std::bind(&ListingMap::onDocumentChanged, this, std::placeholders::_1);

    m_disassembler->busyChanged += [=]() {
        if(m_disassembler->busy())
            return;

        QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
    };
}

QSize ListingMap::sizeHint() const { return QSize(32, 32); }
int ListingMap::calculateSize(u64 sz) const { return (sz * this->itemSize()) / m_totalsize; }

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

void ListingMap::addItem(const REDasm::ListingItem *item)
{
    if(item->is(REDasm::ListingItem::SegmentItem))
    {
        auto& document = m_disassembler->document();
        m_totalsize += document->segment(item->address)->size();

        auto it = REDasm::Listing::insertionPoint(&m_segments, item);
        m_segments.insert(it, item);
    }
    else if(item->is(REDasm::ListingItem::FunctionItem))
    {
        auto it = REDasm::Listing::insertionPoint(&m_functions, item);
        m_functions.insert(it, item);
    }
}

void ListingMap::removeItem(const REDasm::ListingItem *item)
{
    if(item->is(REDasm::ListingItem::SegmentItem))
    {
        auto& document = m_disassembler->document();
        m_totalsize -= document->segment(item->address)->size();

        int idx = REDasm::Listing::indexOf(&m_segments, item);
        m_segments.removeAt(idx);
    }
    else if(item->is(REDasm::ListingItem::FunctionItem))
    {
        int idx = REDasm::Listing::indexOf(&m_functions, item);
        m_functions.removeAt(idx);
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
    QHash<REDasm::Segment*, int> origins;
    auto& document = m_disassembler->document();
    int p = 0, size = 0;

    painter.fillRect(this->rect(), Qt::gray);
    painter.setPen(Qt::gray);

    for(const REDasm::ListingItem* item : m_segments)
    {
        REDasm::Segment* segment = document->segment(item->address);
        QRect r = this->buildRect(0, this->calculateSize(segment->size()));

        if(segment->is(REDasm::SegmentTypes::Code))
            painter.fillRect(r, THEME_VALUE("label_fg"));
        else
            painter.fillRect(r, THEME_VALUE("data_fg"));

        origins[segment] = p;
        p += m_orientation == Qt::Horizontal ? r.width() : r.height();
    }

    if(m_disassembler->busy()) // Don't render functions when disassembler is busy
        return;

    p = 0;

    for(int i = 0; i < m_functions.size(); i++)
    {
        const REDasm::ListingItem* item = m_functions[i];
        REDasm::Segment* segment = document->segment(item->address);

        if(item == m_functions.last())
            size = segment->size();
        else
            size = m_functions[i + 1]->address - item->address;

        REDasm::SymbolPtr symbol = document->symbol(item->address);
        QRect r = this->buildRect(origins[segment] + p, this->calculateSize(size));

        if(symbol->isLocked())
            painter.fillRect(r, THEME_VALUE("locked_fg"));
        else
            painter.fillRect(r, THEME_VALUE("function_fg"));

        painter.drawRect(r.adjusted(0, -1, 0, +1));
        p += m_orientation == Qt::Horizontal ? r.width() : r.height();
    }
}

void ListingMap::resizeEvent(QResizeEvent *e)
{
    QWidget::resizeEvent(e);

    if(this->checkOrientation())
        this->update();
}
