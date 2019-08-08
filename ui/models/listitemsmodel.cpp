#include "listitemsmodel.h"
#include "../../convert.h"

ListItemsModel::ListItemsModel(const REDasm::List &items, QObject *parent): QAbstractListModel(parent), m_items(items) { }
int ListItemsModel::rowCount(const QModelIndex &parent) const { return m_items.size(); }

QVariant ListItemsModel::data(const QModelIndex &index, int role) const
{
    const auto& item = m_items[index.row()];

    if(role == Qt::DisplayRole)
        return Convert::to_qstring(item.toString());

    return QVariant();
}
