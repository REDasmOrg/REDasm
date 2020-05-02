#pragma once

#include "../listingitemmodel.h"

class FunctionListModel : public ListingItemModel
{
    Q_OBJECT

    public:
        explicit FunctionListModel(QObject *parent = nullptr);
        const RDGraph* graph(const QModelIndex& index) const;

    public:
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
};

