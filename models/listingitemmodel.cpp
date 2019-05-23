#include "listingitemmodel.h"
#include <core/disassembler/listing/listingdocument.h>
#include <core/support/demangler.h>
#include <core/plugins/loader.h>
#include "../themeprovider.h"
#include <QColor>

ListingItemModel::ListingItemModel(size_t itemtype, QObject *parent) : DisassemblerModel(parent), m_itemtype(itemtype) { }

void ListingItemModel::setDisassembler(const REDasm::DisassemblerPtr& disassembler)
{
    DisassemblerModel::setDisassembler(disassembler);
    auto& document = m_disassembler->document();

    this->beginResetModel();

    for(auto it = document->begin(); it != document->end(); it++)
    {
        if(!this->isItemAllowed(it->get()))
            continue;

        m_items.insert((*it)->address);
    }

    this->endResetModel();

    EVENT_CONNECT(document, changed, this, std::bind(&ListingItemModel::onListingChanged, this, std::placeholders::_1));
}

const REDasm::ListingItem *ListingItemModel::item(const QModelIndex &index) const
{
    if(!index.isValid() || (index.row() >= m_items.size()))
        return nullptr;

    auto lock = REDasm::s_lock_safe_ptr(m_disassembler->document());
    REDasm::ListingDocumentType::const_iterator it = lock->end();

    if(m_itemtype == REDasm::ListingItem::SegmentItem)
        it = lock->segmentItem(m_items[index.row()]);
    else if(m_itemtype == REDasm::ListingItem::FunctionItem)
        it = lock->functionItem(m_items[index.row()]);
    else
    {
        it = lock->instructionItem(m_items[index.row()]); // Try to get an instruction

        if(it == lock->end())
            it = lock->symbolItem(m_items[index.row()]);  // Try to get an symbol
    }

    return (it != lock->end()) ? it->get() : nullptr;
}

address_location ListingItemModel::address(const QModelIndex &index) const
{
    if(!index.isValid() || (index.row() < 0) || (index.row() >= m_items.size()))
        return REDasm::invalid_location<address_t>();

    return REDasm::make_location(m_items[index.row()]);
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
    const REDasm::Symbol* symbol = lock->symbol(m_items[index.row()]);

    if(!symbol)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(symbol->address, m_disassembler->assembler()->bits()));

        if(index.column() == 1)
        {
            if(symbol->is(REDasm::SymbolType::WideStringMask))
                return S_TO_QS(REDasm::quoted(m_disassembler->readWString(symbol)));
            else if(symbol->is(REDasm::SymbolType::StringMask))
                return S_TO_QS(REDasm::quoted(m_disassembler->readString(symbol)));

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
        int idx = static_cast<int>(m_items.indexOf(ldc->item->address));
        this->beginRemoveRows(QModelIndex(), idx, idx);
        m_items.eraseAt(static_cast<size_t>(idx));
        this->endRemoveRows();
    }
    else if(ldc->isInserted())
    {
        int idx = static_cast<int>(m_items.insertionIndex(ldc->item->address));
        this->beginInsertRows(QModelIndex(), idx, idx);
        m_items.insert(ldc->item->address);
        this->endInsertRows();
    }
}
