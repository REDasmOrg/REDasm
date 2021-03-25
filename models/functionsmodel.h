#pragma once

#include "addressmodel.h"

class FunctionsModel : public AddressModel
{
    Q_OBJECT

    public:
        explicit FunctionsModel(const RDContextPtr& ctx, QObject* parent = 0);
        QString function(const QModelIndex& index) const;
        rd_address address(const QModelIndex& index) const override;
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int columnCount(const QModelIndex& = QModelIndex()) const override;
        int rowCount(const QModelIndex& = QModelIndex()) const override;

    private:
        QString function(const QModelIndex& index, rd_address* address) const;
};

