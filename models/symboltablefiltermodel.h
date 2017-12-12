#ifndef SYMBOLTABLEFILTERMODEL_H
#define SYMBOLTABLEFILTERMODEL_H

#include <QSortFilterProxyModel>
#include "symboltablemodel.h"

class SymbolTableFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

    public:
        explicit SymbolTableFilterModel(QObject *parent = 0);
        REDasm::SymbolPtr symbol(const QModelIndex index) const;
        const QString& filterName() const;
        void setDisassembler(REDasm::Disassembler* disassembler);
        void setSymbolFlags(u32 symbolflags);
        void setFilterName(const QString& name);
        void reloadSymbols();

    protected:
        virtual bool filterAcceptsRow(int source_row, const QModelIndex&) const;

    private:
        QString _filtername;
};

#endif // SYMBOLTABLEFILTERMODEL_H
