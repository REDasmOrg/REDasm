#ifndef GOTOFILTERMODEL_H
#define GOTOFILTERMODEL_H

#include <QSortFilterProxyModel>
#include "gotomodel.h"

class GotoFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

    public:
        explicit GotoFilterModel(QObject *parent = nullptr);
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);

    protected:
        bool filterAcceptsRow(int sourcerow, const QModelIndex &sourceparent) const override;
};

#endif // GOTOFILTERMODEL_H
