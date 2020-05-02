#include "listingitemmodel.h"
#include "../themeprovider.h"
#include <rdapi/support.h>
#include <algorithm>
#include <cassert>
#include <tuple>
#include <QColor>

ListingItemModel::ListingItemModel(type_t itemtype, QObject *parent) : DisassemblerModel(parent), m_itemtype(itemtype) { }
ListingItemModel::~ListingItemModel() { std::for_each(m_events.begin(), m_events.end(), RDEvent_Unsubscribe); }

void ListingItemModel::setDisassembler(RDDisassembler* disassembler)
{
    DisassemblerModel::setDisassembler(disassembler);

    // Prepopulate model with allowed items, if any
    this->beginResetModel();

    size_t c = RDDocument_ItemsCount(m_document);

    for(size_t i = 0; i < c; i++)
    {
        RDDocumentItem item;
        RDDocument_GetItemAt(m_document, i, &item);
        this->insertItem(item);
    }

    this->endResetModel();

    m_events.insert(RDEvent_Subscribe(Event_DocumentChanged, [](const RDEventArgs* e, void* userdata) {
        const RDDocumentEventArgs* de = reinterpret_cast<const RDDocumentEventArgs*>(e);
        ListingItemModel* thethis = reinterpret_cast<ListingItemModel*>(userdata);

        switch(de->action) {
            case DocumentAction_ItemChanged:  thethis->onItemChanged(e);  break;
            case DocumentAction_ItemInserted: thethis->onItemInserted(e); break;
            case DocumentAction_ItemRemoved:  thethis->onItemRemoved(e);  break;
            default: assert(false);
        }
    }, this));
}

const RDDocumentItem& ListingItemModel::item(const QModelIndex &index) const { return m_items[index.row()]; }
int ListingItemModel::rowCount(const QModelIndex &) const { return m_document ? m_items.size() : 0; }
int ListingItemModel::columnCount(const QModelIndex &) const { return 4; }

QVariant ListingItemModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical) return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(section == 0)      return "Address";
        else if(section == 1) return "Symbol";
        else if(section == 2) return "R";
        else if(section == 3) return "Segment";
    }

    return DisassemblerModel::headerData(section, orientation, role);
}

QVariant ListingItemModel::data(const QModelIndex &index, int role) const
{
    if(!m_document) return QVariant();

    RDSymbol symbol;
    if(!RDDocument_GetSymbolByAddress(m_document, m_items[index.row()].address, &symbol)) return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return RD_ToHex(symbol.address);

        if(index.column() == 1)
        {
            if(symbol.type == SymbolType_String)
            {
                RDBlock block;
                if(!RDDocument_GetBlock(m_document, symbol.address, &block)) return QVariant();

                size_t len = RDBlock_Size(&block);

                if(symbol.flags & SymbolFlags_WideString)
                {
                    auto* wptr = RD_ReadWString(m_disassembler, symbol.address, &len);
                    return wptr ? ListingItemModel::escapeString(QString::fromUtf16(wptr, len)) : QVariant();
                }

                auto* ptr = RD_ReadString(m_disassembler, symbol.address, &len);
                return ptr ? ListingItemModel::escapeString(QString::fromLatin1(ptr, len)) : QVariant();
            }

            return RD_Demangle(RDDocument_GetSymbolName(m_document, symbol.address));
        }

        if(index.column() == 2) return QString::number(RDDisassembler_GetReferencesCount(m_disassembler, symbol.address));

        if(index.column() == 3)
        {
            RDSegment segment;
            return RDDocument_GetSegmentAddress(m_document, symbol.address, &segment) ? segment.name : "???";
        }
    }
    else if(role == Qt::BackgroundRole)
    {
        if(symbol.flags & SymbolFlags_EntryPoint) return THEME_VALUE("entrypoint_bg");
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0) return THEME_VALUE("address_list_fg");
        if(symbol.type == SymbolType_String && (index.column() == 1)) return THEME_VALUE("string_fg");
    }

    return QVariant();
}

bool ListingItemModel::isItemAllowed(const RDDocumentItem& item) const
{
    if(m_itemtype == DocumentItemType_All) return true;
    return item.type == m_itemtype;
}

QString ListingItemModel::escapeString(const QString& s)
{
    QString res;

    for(const QChar& ch : s)
    {
        switch(ch.toLatin1())
        {
            case '\n': res += R"(\n)"; break;
            case '\r': res += R"(\r)"; break;
            case '\t': res += R"(\t)"; break;
            default: res += ch; break;
        }
    }

    return res;
}

void ListingItemModel::insertItem(const RDDocumentItem& item)
{
    if(!this->isItemAllowed(item)) return;

    auto it = std::upper_bound(m_items.begin(), m_items.end(), item, [](const auto& item1, const auto& item2) {
        return item1.address < item2.address;
    });

    int idx = static_cast<int>(std::distance(m_items.begin(), it));

    this->beginInsertRows(QModelIndex(), idx, idx);
    m_items.insert(it, item);
    this->endInsertRows();
}

void ListingItemModel::onItemChanged(const RDEventArgs* e)
{
    const RDDocumentEventArgs* de = reinterpret_cast<const RDDocumentEventArgs*>(e);
    if(!this->isItemAllowed(de->item)) return;

    auto it = std::find_if(m_items.begin(), m_items.end(), [&de](const auto& item) {
        return std::tie(de->item.address, de->item.type, de->item.index) ==
               std::tie(item.address, item.type, item.index);
    });

    if(it == m_items.end()) return;

    int idx = static_cast<int>(std::distance(m_items.begin(), it));
    emit dataChanged(this->index(idx, 0), this->index(idx, this->columnCount() - 1));
}

void ListingItemModel::onItemInserted(const RDEventArgs* e)
{
    const RDDocumentEventArgs* de = reinterpret_cast<const RDDocumentEventArgs*>(e);
    this->insertItem(de->item);
}

void ListingItemModel::onItemRemoved(const RDEventArgs* e)
{
    const RDDocumentEventArgs* de = reinterpret_cast<const RDDocumentEventArgs*>(e);
    if(!this->isItemAllowed(de->item)) return;

    auto it = std::find_if(m_items.begin(), m_items.end(), [&de](const auto& item) {
        return std::tie(de->item.address, de->item.type, de->item.index) ==
               std::tie(item.address, item.type, item.index);
    });

    if(it == m_items.end()) return;

    int idx = static_cast<int>(std::distance(m_items.begin(), it));

    this->beginRemoveRows(QModelIndex(), idx, idx);
    m_items.erase(it);
    this->endRemoveRows();
}
