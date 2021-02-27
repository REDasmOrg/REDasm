#pragma once

#include "contextmodel.h"

class AddressModel : public ContextModel
{
    Q_OBJECT

    public:
        explicit AddressModel(const RDContextPtr& ctx, QObject *parent = nullptr);
        virtual rd_address address(const QModelIndex& index) const = 0;
};
