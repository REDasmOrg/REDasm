#pragma once

#include <QAbstractListModel>
#include <rdapi/rdapi.h>

class CheckedItemsModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        CheckedItemsModel(RDUIOptions* options, size_t c, QObject* parent = nullptr);
        void uncheckAll();

    public:
        Qt::ItemFlags flags(const QModelIndex &index) const override;
        int rowCount(const QModelIndex&) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
        bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;

    private:
        RDUIOptions* m_options;
        size_t m_count;
};
