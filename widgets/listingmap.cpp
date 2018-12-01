#include "listingmap.h"
#include "../themeprovider.h"
#include <QPainter>
#include <cmath>

ListingMap::ListingMap(QWidget *parent) : QWidget(parent), m_disassembler(NULL), m_totalsize(0) { }

void ListingMap::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    m_disassembler = disassembler;

    REDasm::ListingDocument* doc = m_disassembler->document();

    for(auto it = doc->begin(); it != doc->end(); it++)
        this->addItem(it->get());

    this->update();

    doc->changed += std::bind(&ListingMap::onDocumentChanged, this, std::placeholders::_1);

    m_disassembler->busyChanged += [=]() {
        if(m_disassembler->busy())
            return;

        QMetaObject::invokeMethod(this, "update");
    };
}

int ListingMap::calculateWidth(u64 sz) const { return (sz * this->width()) / m_totalsize; }

void ListingMap::addItem(const REDasm::ListingItem *item)
{
    if(item->is(REDasm::ListingItem::SegmentItem))
    {
        REDasm::ListingDocument* doc = m_disassembler->document();
        m_totalsize += doc->segment(item->address)->size();

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
        REDasm::ListingDocument* doc = m_disassembler->document();
        m_totalsize -= doc->segment(item->address)->size();

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
    REDasm::ListingDocument* doc = m_disassembler->document();
    int x = 0, size = 0;

    painter.fillRect(this->rect(), Qt::gray);
    painter.setPen(Qt::gray);

    for(const REDasm::ListingItem* item : m_segments)
    {
        REDasm::Segment* segment = doc->segment(item->address);
        QRect r(x, 0, this->calculateWidth(segment->size()), this->height());

        if(segment->is(REDasm::SegmentTypes::Code))
            painter.fillRect(r, THEME_VALUE("label_fg"));
        else
            painter.fillRect(r, THEME_VALUE("data_fg"));

        origins[segment] = x;
        x += r.width();
    }

    x = 0;

    for(int i = 0; i < m_functions.size(); i++)
    {
        const REDasm::ListingItem* item = m_functions[i];
        REDasm::Segment* segment = doc->segment(item->address);

        if(item == m_functions.last())
            size = segment->size();
        else
            size = m_functions[i + 1]->address - item->address;

        REDasm::SymbolPtr symbol = doc->symbol(item->address);
        QRect r(origins[segment] + x, 0, this->calculateWidth(size), this->height());

        if(symbol->isLocked())
            painter.fillRect(r, THEME_VALUE("locked_fg"));
        else
            painter.fillRect(r, THEME_VALUE("function_fg"));

        painter.drawRect(r.adjusted(0, -1, 0, +1));
        x += r.width();
    }
}
