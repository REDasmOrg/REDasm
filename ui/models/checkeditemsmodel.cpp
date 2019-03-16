#include "checkeditemsmodel.h"

CheckedItemsModel::CheckedItemsModel(REDasm::UI::CheckList &items, QObject *parent): QAbstractListModel(parent), m_items(items) { }

void CheckedItemsModel::uncheckAll()
{
    this->beginResetModel();

    for(auto& item : m_items)
        item.second = false;

    this->endResetModel();
}

Qt::ItemFlags CheckedItemsModel::flags(const QModelIndex &index) const { return QAbstractListModel::flags(index) | Qt::ItemIsUserCheckable; }
int CheckedItemsModel::rowCount(const QModelIndex &parent) const { return m_items.size(); }

QVariant CheckedItemsModel::data(const QModelIndex &index, int role) const
{
    const auto& item = m_items[index.row()];

    if(role == Qt::DisplayRole)
        return QString::fromStdString(item.first);
    if(role == Qt::CheckStateRole)
        return item.second ? Qt::Checked : Qt::Unchecked;

    return QVariant();
}

bool CheckedItemsModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(role == Qt::CheckStateRole)
    {
        auto& item = m_items[index.row()];
        item.second = value == Qt::Checked ? true : false;
        emit dataChanged(index, index);
        return true;
    }

    return QAbstractListModel::setData(index, value, role);
}
