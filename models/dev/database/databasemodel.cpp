#include "databasemodel.h"
#include "../../../redasmfonts.h"

DatabaseModel::DatabaseModel(QObject *parent) : QAbstractListModel(parent) { }

DatabaseDataModel* DatabaseModel::dataModel(const QModelIndex& index) const
{
    if(index.row() < 0) return nullptr;
    if(index.row() >= static_cast<int>(m_dblist.size())) return nullptr;

    auto it = m_dbdata.find(m_dblist[index.row()].get());
    if(it == m_dbdata.end()) return nullptr;

    it->second->query();
    return it->second;
}

int DatabaseModel::columnCount(const QModelIndex&) const { return 1; }
int DatabaseModel::rowCount(const QModelIndex&) const { return m_dblist.size(); }

QVariant DatabaseModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid()) return QVariant();

    const auto& db = m_dblist[index.row()];
    if(!db) return QVariant();

    if(role == Qt::DisplayRole) return RDDatabase_GetName(db.get());
    else if(role == Qt::DecorationRole) return FA_ICON(0xf1c0);

    return QVariant();
}

QModelIndex DatabaseModel::addDatabase(RDDatabase* db)
{
    int idx = m_dblist.size();

    this->beginInsertRows(QModelIndex(), idx, idx);
    m_dblist.emplace_back(db);
    m_dbdata[db] = new DatabaseDataModel(db, this);
    this->endInsertRows();

    return this->index(idx);
}
