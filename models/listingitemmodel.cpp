#include "listingitemmodel.h"
#include "../themeprovider.h"
#include <algorithm>
#include <iostream>
#include <tuple>
#include <QColor>

ListingItemModel::ListingItemModel(rd_type itemtype, QObject *parent) : ContextModel(parent), m_itemtype(itemtype) { }
ListingItemModel::~ListingItemModel() { if(m_context) RDObject_Unsubscribe(m_context.get(), this); }

void ListingItemModel::setContext(const RDContextPtr& disassembler)
{
    ContextModel::setContext(disassembler);

    RDObject_Subscribe(m_context.get(), this, [](const RDEventArgs* e) {
        if(e->id != Event_DocumentChanged) return;
        ListingItemModel* thethis = reinterpret_cast<ListingItemModel*>(e->owner);
        const RDDocumentEventArgs* de = reinterpret_cast<const RDDocumentEventArgs*>(e);

        switch(de->action) {
            case DocumentAction_ItemInserted: thethis->insertItem(de->item); break;
            case DocumentAction_ItemRemoved:  thethis->onItemRemoved(de);    break;
            case DocumentAction_ItemChanged:  thethis->onItemChanged(de);    break;
            default: break;
        }

    }, nullptr);

    // Prepopulate model with allowed items, if any
    this->beginResetModel();
    m_items.clear();

    RDDocument_Each(m_document, [](const RDDocumentItem* item, void* userdata) {
        auto* thethis = reinterpret_cast<ListingItemModel*>(userdata);
        thethis->insertItem(*item);
        return true;
    }, this);

    this->endResetModel();
}

const RDDocumentItem& ListingItemModel::item(size_t index) const { return m_items[index]; }
const RDDocumentItem& ListingItemModel::item(const QModelIndex &index) const { return m_items[index.row()]; }
rd_type ListingItemModel::itemType() const { return m_itemtype; }
int ListingItemModel::rowCount(const QModelIndex &) const { return m_document ? m_items.size() : 0; }
int ListingItemModel::columnCount(const QModelIndex &) const { return 4; }

QVariant ListingItemModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical) return QVariant();

    if(role == Qt::DisplayRole)
    {
        switch(section)
        {
            case 0: return "Address";
            case 1: return "Segment";
            case 2: return "R";
            case 3: return "Symbol";
            default: break;
        }
    }

    return ContextModel::headerData(section, orientation, role);
}

QVariant ListingItemModel::data(const QModelIndex &index, int role) const
{
    if(!m_document) return QVariant();

    RDSymbol symbol;

    if(!RDDocument_GetSymbolByAddress(m_document, m_items[index.row()].address, &symbol))
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return RD_ToHexAuto(symbol.address);

        if(index.column() == 1)
        {
            RDSegment segment;
            return RDDocument_GetSegmentAddress(m_document, symbol.address, &segment) ? segment.name : "???";
        }

        if(index.column() == 2)
        {
            const RDNet* net = RDContext_GetNet(m_context.get());
            return QString::number(RDNet_GetReferences(net, symbol.address, nullptr));
        }

        if(index.column() == 3)
        {
            if(IS_TYPE(&symbol, SymbolType_String))
            {
                RDBlock block;
                if(!RDDocument_GetBlock(m_document, symbol.address, &block)) return QVariant();

                size_t len = RDBlock_Size(&block);

                if(HAS_FLAG(&symbol, SymbolFlags_WideString))
                {
                    auto* wptr = RD_ReadWString(this->context().get(), symbol.address, &len);
                    return wptr ? ListingItemModel::escapeString(QString::fromUtf16(wptr, len)) : QVariant();
                }

                auto* ptr = RD_ReadString(this->context().get(), symbol.address, &len);
                return ptr ? ListingItemModel::escapeString(QString::fromLatin1(ptr, len)) : QVariant();
            }

            return RD_Demangle(RDDocument_GetSymbolName(m_document, symbol.address));
        }
    }
    else if(role == Qt::TextAlignmentRole)
    {
        return (index.column() < 3) ? Qt::AlignCenter : Qt::AlignLeft;
    }
    else if(role == Qt::BackgroundRole)
    {
        if(HAS_FLAG(&symbol, SymbolFlags_EntryPoint)) return THEME_VALUE(Theme_EntryBg);
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0) return THEME_VALUE(Theme_Address);
        if(HAS_FLAG(&symbol, SymbolFlags_EntryPoint)) return THEME_VALUE(Theme_EntryFg);
        if(IS_TYPE(&symbol, SymbolType_String) && (index.column() == 3)) return THEME_VALUE(Theme_String);
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

void ListingItemModel::onItemChanged(const RDDocumentEventArgs* e)
{
    if(!this->isItemAllowed(e->item)) return;

    auto it = std::find_if(m_items.begin(), m_items.end(), [&e](const auto& item) {
        return std::tie(e->item.address, e->item.type, e->item.index) ==
               std::tie(item.address, item.type, item.index);
    });

    if(it == m_items.end()) return;

    int idx = static_cast<int>(std::distance(m_items.begin(), it));
    emit dataChanged(this->index(idx, 0), this->index(idx, this->columnCount() - 1));
}

void ListingItemModel::onItemRemoved(const RDDocumentEventArgs* e)
{
    if(!this->isItemAllowed(e->item)) return;

    auto it = std::find_if(m_items.begin(), m_items.end(), [&e](const auto& item) {
        return std::tie(e->item.address, e->item.type, e->item.index) ==
               std::tie(item.address, item.type, item.index);
    });

    if(it == m_items.end()) return;

    int idx = static_cast<int>(std::distance(m_items.begin(), it));

    this->beginRemoveRows(QModelIndex(), idx, idx);
    m_items.erase(it);
    this->endRemoveRows();
}
