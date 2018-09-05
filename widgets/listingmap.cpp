#include "listingmap.h"
#include <QPainter>
#include <cmath>

#define SCALE_TO_WIDGET(v, w) std::ceil((v * w) / static_cast<double>(this->_size))

ListingMap::ListingMap(QWidget *parent) : QWidget(parent), _size(0)
{

}

void ListingMap::render(REDasm::Disassembler* disassembler)
{
    /*
    u64 reloffset = 0;
    const REDasm::SegmentList& segments = disassembler->format()->segments();

    this->_size = 0;
    this->_segments.clear();
    this->_functions.clear();

    std::for_each(segments.begin(), segments.end(), [this, &reloffset](const REDasm::Segment& segment) {

        Item item;
        item.address = segment.address;
        item.offset = reloffset;
        item.size = segment.size();

        if((segment.type & REDasm::SegmentTypes::Code) && (segment.type & REDasm::SegmentTypes::Data))
            item.color = QColor(Qt::darkGreen);
        else if(segment.type & REDasm::SegmentTypes::Code)
            item.color = QColor(Qt::darkMagenta);
        else if(segment.type & REDasm::SegmentTypes::Data)
            item.color = QColor(Qt::darkRed);
        else
            item.color = QColor(Qt::gray);

        this->_segments[reloffset] = item;
        reloffset += item.size;
    });

    this->_size = reloffset;

    disassembler->symbolTable()->iterate(REDasm::SymbolTypes::FunctionMask, [this, disassembler](REDasm::SymbolPtr symbol) -> bool {
        const Item* segmentitem = this->segmentBase(disassembler, symbol);

        if(!segmentitem)
            return true;

        std::string sig = disassembler->instructions().getSignature(symbol);

        if(sig.empty())
            return true;

        Item item;
        item.address = symbol->address;
        item.offset = segmentitem->offset + (symbol->address - segmentitem->address);
        item.size = sig.size();

        if(symbol->type & REDasm::SymbolTypes::Locked)
            item.color = QColor(Qt::magenta);
        else
            item.color = QColor(Qt::blue);

        this->_functions[symbol->address] = item;
        return true;
    });

    this->update();
    */
}

const ListingMap::Item* ListingMap::segmentBase(REDasm::Disassembler* disassembler, REDasm::SymbolPtr symbol) const
{
    /*
    const REDasm::Segment* segment = disassembler->format()->segment(symbol->address);

    if(!segment)
        return NULL;

    foreach(const Item& item, this->_segments)
    {
        if(item.address == segment->address)
            return &item;
    }
    */

    return NULL;
}

void ListingMap::paintEvent(QPaintEvent *)
{
    /*
    QPainter painter(this);
    int w = this->width(), h = this->height();

    foreach(const Item& item, this->_segments)
    {
        QRect r(SCALE_TO_WIDGET(item.offset, w), 0, SCALE_TO_WIDGET(item.size, w), h);
        painter.fillRect(r, item.color);
    }

    foreach(const Item& item, this->_functions)
    {
        QRect r(SCALE_TO_WIDGET(item.offset, w), 0, SCALE_TO_WIDGET(item.size, w), h);
        painter.fillRect(r, item.color);
    }
    */
}
