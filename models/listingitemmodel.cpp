#include "listingitemmodel.h"
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/plugins/loader/loader.h>
#include <redasm/support/demangler.h>
#include <redasm/support/utils.h>
#include "../themeprovider.h"
#include <QColor>

ListingItemModel::ListingItemModel(REDasm::ListingItemType itemtype, QObject *parent) : DisassemblerModel(parent), m_itemtype(itemtype) { }

void ListingItemModel::setDisassembler(const REDasm::DisassemblerPtr& disassembler)
{
    DisassemblerModel::setDisassembler(disassembler);
    auto& document = m_disassembler->document();

    this->beginResetModel();

    for(size_t i = 0; i < document->size(); i++)
    {
        const REDasm::ListingItem* item = document->itemAt(i);

        if(!this->isItemAllowed(item))
            continue;

        m_items.insert(item->address());
    }

    this->endResetModel();
    EVENT_CONNECT(document, changed, this, std::bind(&ListingItemModel::onListingChanged, this, std::placeholders::_1));
}

const REDasm::ListingItem *ListingItemModel::item(const QModelIndex &index) const
{
    if(!index.isValid() || (index.row() >= m_items.size()))
        return nullptr;

    auto lock = REDasm::s_lock_safe_ptr(m_disassembler->document());
    REDasm::ListingItem* item = nullptr;

    if(m_itemtype == REDasm::ListingItemType::SegmentItem)
        item = lock->segmentItem(m_items[index.row()].toU64());
    else if(m_itemtype == REDasm::ListingItemType::FunctionItem)
        item = lock->functionItem(m_items[index.row()].toU64());
    else
    {
        item = lock->instructionItem(m_items[index.row()].toU64()); // Try to get an instruction

        if(!item)
            item = lock->symbolItem(m_items[index.row()].toU64());  // Try to get an symbol
    }

    return item;
}

address_location ListingItemModel::address(const QModelIndex &index) const
{
    if(!index.isValid() || (index.row() < 0) || (index.row() >= m_items.size()))
        return REDasm::invalid_location<address_t>();

    return REDasm::make_location(m_items[index.row()].toU64());
}

QModelIndex ListingItemModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent)

    if((row < 0) || (row >= m_items.size()))
        return QModelIndex();

    return this->createIndex(row, column);
}

int ListingItemModel::rowCount(const QModelIndex &) const { return m_items.size(); }
int ListingItemModel::columnCount(const QModelIndex &) const { return 4; }

QVariant ListingItemModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(section == 0)
            return "Address";
        else if(section == 1)
            return "Symbol";
        else if(section == 2)
            return "R";
        else if(section == 3)
            return "Segment";
    }

    return DisassemblerModel::headerData(section, orientation, role);
}

QVariant ListingItemModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    auto lock = REDasm::s_lock_safe_ptr(m_disassembler->document());
    const REDasm::Symbol* symbol = lock->symbol(m_items[index.row()].toU64());

    if(!symbol)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::String::hex(symbol->address, m_disassembler->assembler()->bits()));

        if(index.column() == 1)
        {
            if(symbol->is(REDasm::SymbolType::WideStringMask))
                return S_TO_QS(m_disassembler->readWString(symbol).quoted());
            else if(symbol->is(REDasm::SymbolType::StringMask))
                return S_TO_QS(m_disassembler->readString(symbol).quoted());

            return S_TO_QS(REDasm::Demangler::demangled(symbol->name));
        }

        if(index.column() == 2)
            return QString::number(m_disassembler->getReferencesCount(symbol->address));

        if(index.column() == 3)
        {
            REDasm::Segment* segment = lock->segment(symbol->address);

            if(segment)
                return S_TO_QS(segment->name);

            return "???";
        }
    }
    else if(role == Qt::BackgroundRole)
    {
        if(symbol->isFunction() && symbol->isLocked())
            return THEME_VALUE("locked_bg");
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0)
            return THEME_VALUE("address_list_fg");

        if(symbol->is(REDasm::SymbolType::String) && (index.column() == 1))
            return THEME_VALUE("string_fg");
    }

    return QVariant();
}

bool ListingItemModel::isItemAllowed(const REDasm::ListingItem *item) const
{
    if(m_itemtype == REDasm::ListingItemType::AllItems)
        return true;

    return item->is(m_itemtype);
}

void ListingItemModel::onListingChanged(const REDasm::ListingDocumentChanged *ldc)
{
    if(!this->isItemAllowed(ldc->item()))
        return;

    if(ldc->isRemoved())
    {
        int idx = static_cast<int>(m_items.indexOf(ldc->item()->address()));
        this->beginRemoveRows(QModelIndex(), idx, idx);
        m_items.removeAt(static_cast<size_t>(idx));
        this->endRemoveRows();
    }
    else if(ldc->isInserted())
    {
        int idx = static_cast<int>(m_items.insertionIndex(ldc->item()->address()));
        this->beginInsertRows(QModelIndex(), idx, idx);
        m_items.insert(ldc->item()->address());
        this->endInsertRows();
    }
}
