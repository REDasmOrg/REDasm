#pragma once

#include <QAbstractItemModel>
#include <rdapi/rdapi.h>
#include <vector>
#include "databasedatamodel.h"

class DatabaseModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit DatabaseModel(QObject *parent = nullptr);
        DatabaseDataModel* dataModel(const QModelIndex& index) const;
        int rowCount(const QModelIndex&) const override;
        int columnCount(const QModelIndex&) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
        QModelIndex addDatabase(RDDatabase* db);

    private:
        std::vector<rd_ptr<RDDatabase>> m_dblist;
        std::unordered_map<RDDatabase*, DatabaseDataModel*> m_dbdata;
};

