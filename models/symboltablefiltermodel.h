#ifndef SYMBOLTABLEFILTERMODEL_H
#define SYMBOLTABLEFILTERMODEL_H

#include <QSortFilterProxyModel>
#include "symboltablemodel.h"

class SymbolTableFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

    public:
        explicit SymbolTableFilterModel(QObject *parent = 0);
        const QString& filterName() const;
        void setDisassembler(REDasm::Disassembler* disassembler);
        void setFilterName(const QString& name);
        void setFilterSymbol(u32 flags);

    protected:
        virtual bool filterAcceptsRow(int source_row, const QModelIndex&) const;

    private:
        SymbolTableModel* _symboltablemodel;
        QString _filtername;
        u32 _filtersymbol;
};

#endif // SYMBOLTABLEFILTERMODEL_H
