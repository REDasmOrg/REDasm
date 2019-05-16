#include "gotomodel.h"
#include "../themeprovider.h"
#include <redasm/plugins/loader.h>

GotoModel::GotoModel(QObject *parent) : ListingItemModel(REDasm::ListingItem::AllItems, parent) { }
GotoModel::~GotoModel() { EVENT_DISCONNECT(m_disassembler->document(), changed, this);  }

QVariant GotoModel::data(const QModelIndex &index, int role) const
{
    if(!m_disassembler)
        return QVariant();

    const REDasm::ListingItem* item = this->item(index);

    if(!item)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(item->address, m_disassembler->assembler()->bits()));
        if(index.column() == 1)
            return this->itemName(item);
        if(index.column() == 2)
            return this->itemType(item);
    }
    else if(role == Qt::TextAlignmentRole)
    {
        if(index.column() == 2)
            return Qt::AlignCenter;
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0)
            return THEME_VALUE("address_list_fg");

        if(index.column() == 1)
            return this->itemColor(item);
    }

    return QVariant();
}

QVariant GotoModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(section == 0)
            return "Address";
        else if(section == 1)
            return "Name";
        else if(section == 2)
            return "Type";
    }

    return DisassemblerModel::headerData(section, orientation, role);
}

int GotoModel::columnCount(const QModelIndex &) const { return 3; }

QColor GotoModel::itemColor(const REDasm::ListingItem *item) const
{
    if(item->type == REDasm::ListingItem::SegmentItem)
        return THEME_VALUE("segment_fg");
    if(item->type == REDasm::ListingItem::FunctionItem)
        return THEME_VALUE("function_fg");
    if(item->type == REDasm::ListingItem::TypeItem)
        return THEME_VALUE("type_fg");

    if(item->type == REDasm::ListingItem::SymbolItem)
    {
        const REDasm::ListingDocument& document = m_disassembler->document();
        const REDasm::Symbol* symbol = document->symbol(item->address);

        if(!symbol)
            return QColor();

        if(symbol->is(REDasm::SymbolType::String))
            return THEME_VALUE("string_fg");

        return THEME_VALUE("data_fg");
    }

    return QColor();
}

QString GotoModel::itemName(const REDasm::ListingItem *item) const
{
    const REDasm::ListingDocument& document = m_disassembler->document();

    if(item->type == REDasm::ListingItem::SegmentItem)
    {
        const REDasm::Segment* segment = document->segment(item->address);

        if(segment)
            return S_TO_QS(segment->name);
    }
    else if((item->type == REDasm::ListingItem::FunctionItem) || (item->type == REDasm::ListingItem::SymbolItem))
    {
        const REDasm::Symbol* symbol = document->symbol(item->address);

        if(symbol)
            return S_TO_QS(REDasm::Demangler::demangled(symbol->name));
    }
    else if(item->type == REDasm::ListingItem::TypeItem)
        return S_TO_QS(document->type(item));

    return QString();
}

QString GotoModel::itemType(const REDasm::ListingItem *item) const
{
    if(item->type == REDasm::ListingItem::SegmentItem)
        return "SEGMENT";
    if(item->type == REDasm::ListingItem::FunctionItem)
        return "FUNCTION";
    if(item->type == REDasm::ListingItem::TypeItem)
        return "TYPE";
    if(item->type == REDasm::ListingItem::SymbolItem)
        return "SYMBOL";

    return QString();
}

bool GotoModel::isItemAllowed(const REDasm::ListingItem *item) const
{
    switch(item->type)
    {
        case REDasm::ListingItem::SegmentItem:
        case REDasm::ListingItem::FunctionItem:
        case REDasm::ListingItem::SymbolItem:
        case REDasm::ListingItem::TypeItem:
            return true;

        default:
            break;
    }

    return false;
}
