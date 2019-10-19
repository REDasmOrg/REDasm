#pragma once

#include <QAbstractListModel>

class BlockListModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit BlockListModel(QObject *parent = nullptr);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        QVariant data(const QModelIndex &index, int role) const override;
        int columnCount(const QModelIndex&) const override;
        int rowCount(const QModelIndex&) const override;

    private:
        QString symbolName(const QModelIndex& index) const;
        QString segmentName(int section) const;
};

