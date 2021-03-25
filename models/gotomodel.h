#pragma once

#include "addressmodel.h"
#include <rdapi/rdapi.h>

class GotoModel : public AddressModel
{
    Q_OBJECT

    public:
        explicit GotoModel(const RDContextPtr& ctx, QObject *parent = nullptr);
        rd_address address(const QModelIndex& index) const override;
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int columnCount(const QModelIndex&) const override;
        int rowCount(const QModelIndex&) const override;
};
