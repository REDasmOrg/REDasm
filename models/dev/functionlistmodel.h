#pragma once

#include <QAbstractListModel>

class FunctionListModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit FunctionListModel(QObject *parent = nullptr);

    public:
        QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
        int columnCount(const QModelIndex &parent = QModelIndex()) const override;
        int rowCount(const QModelIndex &parent = QModelIndex()) const override;
};

