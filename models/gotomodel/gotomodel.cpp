#include "gotomodel.h"
#include "../../themeprovider.h"
#include <redasm/disassembler/listing/listingdocumentnew.h>
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/disassembler/disassembler.h>
#include <redasm/support/demangler.h>
#include <redasm/support/utils.h>
#include "../../../convert.h"

GotoModel::GotoModel(QObject *parent) : DisassemblerModel(parent) { }

void GotoModel::setDisassembler(const REDasm::DisassemblerPtr &disassembler)
{
    this->beginResetModel();
    DisassemblerModel::setDisassembler(disassembler);
    this->endResetModel();
}

QVariant GotoModel::data(const QModelIndex &index, int role) const
{
    if(!m_disassembler)
        return QVariant();

    REDasm::ListingItem item = m_disassembler->documentNew()->items()->at(index.row());

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return Convert::to_qstring(REDasm::String::hex(item.address_new, m_disassembler->assembler()->bits()));
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
        if(section == 0)      return "Address";
        else if(section == 1) return "Name";
        else if(section == 2) return "Type";
    }

    return DisassemblerModel::headerData(section, orientation, role);
}

int GotoModel::columnCount(const QModelIndex &) const { return 3; }
int GotoModel::rowCount(const QModelIndex &) const { return m_disassembler ? m_disassembler->documentNew()->items()->size() : 0; }

QColor GotoModel::itemColor(const REDasm::ListingItem& item) const
{
    if(item.is(REDasm::ListingItemType::SegmentItem))  return THEME_VALUE("segment_fg");
    if(item.is(REDasm::ListingItemType::FunctionItem)) return THEME_VALUE("function_fg");
    if(item.is(REDasm::ListingItemType::TypeItem))     return THEME_VALUE("type_fg");

    if(item.is(REDasm::ListingItemType::SymbolItem))
    {
        const auto& document = m_disassembler->documentNew();
        const REDasm::Symbol* symbol = document->symbols()->get(item.address_new);

        if(!symbol) return QColor();
        if(symbol->is(REDasm::SymbolType::String)) return THEME_VALUE("string_fg");
        return THEME_VALUE("data_fg");
    }

    return QColor();
}

QString GotoModel::itemName(const REDasm::ListingItem& item) const
{
    const auto& document = m_disassembler->documentNew();

    if(item.is(REDasm::ListingItemType::SegmentItem))
    {
        const REDasm::Segment* segment = document->segments()->find(item.address_new);
        if(segment) return S_TO_QS(segment->name);
    }
    else if(item.is(REDasm::ListingItemType::FunctionItem) || item.is(REDasm::ListingItemType::SymbolItem))
    {
        const REDasm::Symbol* symbol = document->symbols()->get(item.address_new);
        if(symbol) return S_TO_QS(REDasm::Demangler::demangled(symbol->name));
    }
    //FIXME: else if(item->type() == REDasm::ListingItemType::TypeItem)
        //FIXME: return S_TO_QS(document->type(item));

    return QString();
}

QString GotoModel::itemType(const REDasm::ListingItem& item) const
{
    if(item.is(REDasm::ListingItemType::SegmentItem))  return "SEGMENT";
    if(item.is(REDasm::ListingItemType::FunctionItem)) return "FUNCTION";
    if(item.is(REDasm::ListingItemType::TypeItem))     return "TYPE";
    if(item.is(REDasm::ListingItemType::SymbolItem))   return "SYMBOL";
    return QString();
}
