#include "checkeditemsmodel.h"

CheckedItemsModel::CheckedItemsModel(RDUIOptions* options, size_t c, QObject* parent): QAbstractListModel(parent), m_options(options), m_count(c) { }

void CheckedItemsModel::uncheckAll()
{
    this->beginResetModel();

    for(size_t i = 0; i < m_count; i++)
        m_options[i].selected = false;

    this->endResetModel();
}

Qt::ItemFlags CheckedItemsModel::flags(const QModelIndex &index) const { return QAbstractListModel::flags(index) | Qt::ItemIsUserCheckable; }
int CheckedItemsModel::rowCount(const QModelIndex&) const { return static_cast<int>(m_count); }

QVariant CheckedItemsModel::data(const QModelIndex &index, int role) const
{
    const auto& option = m_options[index.row()];

    if(role == Qt::DisplayRole) return option.text;
    if(role == Qt::CheckStateRole) return option.selected ? Qt::Checked : Qt::Unchecked;

    return QVariant();
}

bool CheckedItemsModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(role == Qt::CheckStateRole)
    {
        auto& option = m_options[index.row()];
        option.selected = value == Qt::Checked ? true : false;
        Q_EMIT dataChanged(index, index);
        return true;
    }

    return QAbstractListModel::setData(index, value, role);
}
