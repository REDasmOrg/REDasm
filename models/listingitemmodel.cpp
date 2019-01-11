#include "listingitemmodel.h"
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/plugins/format.h>
#include "../themeprovider.h"
#include <QColor>

ListingItemModel::ListingItemModel(u32 itemtype, QObject *parent) : DisassemblerModel(parent), m_itemtype(itemtype) { }

void ListingItemModel::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    DisassemblerModel::setDisassembler(disassembler);
    auto& document = m_disassembler->document();

    this->beginResetModel();

    for(auto it = document->begin(); it != document->end(); it++)
    {
        if(!this->isItemAllowed(it->get()))
            continue;

        auto itip = REDasm::Listing::insertionPoint(&m_items, it->get());
        m_items.insert(itip, it->get());
    }

    this->endResetModel();

    document->changed += std::bind(&ListingItemModel::onListingChanged, this, std::placeholders::_1);
}

QModelIndex ListingItemModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent)

    if((row < 0) || (row >= m_items.size()))
        return QModelIndex();

    return this->createIndex(row, column, m_items[row]);
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

    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(index.internalPointer());
    REDasm::SymbolPtr symbol = m_disassembler->document()->symbol(item->address);

    if(!symbol)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(symbol->address, m_disassembler->format()->bits()));

        if(index.column() == 1)
        {
            if(symbol->is(REDasm::SymbolTypes::WideStringMask))
                return S_TO_QS(REDasm::quoted(m_disassembler->readWString(symbol)));
            else if(symbol->is(REDasm::SymbolTypes::StringMask))
                return S_TO_QS(REDasm::quoted(m_disassembler->readString(symbol)));

            return S_TO_QS(symbol->name);
        }

        if(index.column() == 2)
            return QString::number(m_disassembler->getReferencesCount(symbol->address));

        if(index.column() == 3)
        {
            REDasm::Segment* segment = m_disassembler->document()->segment(symbol->address);

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

        if(symbol->is(REDasm::SymbolTypes::String) && (index.column() == 1))
            return THEME_VALUE("string_fg");
    }

    return QVariant();
}

bool ListingItemModel::isItemAllowed(REDasm::ListingItem *item) const
{
    if(m_itemtype == REDasm::ListingItem::AllItems)
        return true;

    return m_itemtype == item->type;
}

void ListingItemModel::onListingChanged(const REDasm::ListingDocumentChanged *ldc)
{
    if(!this->isItemAllowed(ldc->item))
        return;

    if(ldc->isRemoved())
    {
        int idx = REDasm::Listing::indexOf(&m_items, ldc->item);

        this->beginRemoveRows(QModelIndex(), idx, idx);
        m_items.removeAt(idx);
        this->endRemoveRows();
    }
    else if(ldc->isInserted())
    {
        auto it = REDasm::Listing::insertionPoint(&m_items, ldc->item);
        int idx = std::distance(m_items.begin(), it);

        this->beginInsertRows(QModelIndex(), idx, idx);
        m_items.insert(it, ldc->item);
        this->endInsertRows();
    }
}
