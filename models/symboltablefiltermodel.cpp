#include "symboltablefiltermodel.h"

SymbolTableFilterModel::SymbolTableFilterModel(QObject *parent) : QSortFilterProxyModel(parent)
{
    this->setSourceModel(new SymbolTableModel(this));
}

REDasm::SymbolPtr SymbolTableFilterModel::symbol(const QModelIndex index) const
{
    SymbolTableModel* symboltablemodel = static_cast<SymbolTableModel*>(this->sourceModel());
    return symboltablemodel->_symbols[index.row()];
}

const QString &SymbolTableFilterModel::filterName() const
{
    return this->_filtername;
}

void SymbolTableFilterModel::setDisassembler(REDasm::Disassembler *disassembler)
{
    static_cast<SymbolTableModel*>(this->sourceModel())->setDisassembler(disassembler);
}

void SymbolTableFilterModel::setSymbolFlags(u32 symbolflags)
{
    static_cast<SymbolTableModel*>(this->sourceModel())->setSymbolFlags(symbolflags);
}

void SymbolTableFilterModel::setFilterName(const QString &name)
{
    this->_filtername = name;
    this->invalidateFilter();
}

void SymbolTableFilterModel::reloadSymbols()
{
    this->invalidate();
    static_cast<SymbolTableModel*>(this->sourceModel())->loadSymbols();
}

bool SymbolTableFilterModel::filterAcceptsRow(int source_row, const QModelIndex &) const
{
    QModelIndex index = this->sourceModel()->index(source_row, 1);
    const REDasm::Symbol* symbol = reinterpret_cast<const REDasm::Symbol*>(index.internalPointer());
    bool res = true;

    if(!this->_filtername.isEmpty())
    {
        if(symbol->is(REDasm::SymbolTypes::StringMask))
            res &= this->sourceModel()->data(index).toString().indexOf(this->_filtername, 0, Qt::CaseInsensitive) != -1;
        else
            res &= QString::fromStdString(symbol->name).indexOf(this->_filtername, 0, Qt::CaseInsensitive) != -1;
    }

    return res;
}
