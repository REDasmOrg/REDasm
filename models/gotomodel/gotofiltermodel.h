#pragma once

#include <QSortFilterProxyModel>
#include "gotomodel.h"

class GotoFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

    public:
        explicit GotoFilterModel(QObject *parent = nullptr);
        void setContext(const RDContextPtr& ctx);
        const RDDocumentItem& item(const QModelIndex& index) const;

    protected:
        bool filterAcceptsRow(int sourcerow, const QModelIndex &sourceparent) const override;
};
