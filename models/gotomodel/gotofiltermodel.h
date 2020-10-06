#pragma once

#include <QSortFilterProxyModel>
#include "gotomodel.h"

class GotoFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

    public:
        explicit GotoFilterModel(QObject *parent = nullptr);
        void setDisassembler(const RDContextPtr& disassembler);

    protected:
        bool filterAcceptsRow(int sourcerow, const QModelIndex &sourceparent) const override;
};
