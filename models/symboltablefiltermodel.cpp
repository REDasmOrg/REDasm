#include "symboltablefiltermodel.h"

SymbolTableFilterModel::SymbolTableFilterModel(QObject *parent) : QSortFilterProxyModel(parent), _filtersymbol(REDasm::SymbolTypes::None)
{
    this->setSourceModel(new SymbolTableModel(this));
}

const QString &SymbolTableFilterModel::filterName() const
{
    return this->_filtername;
}

void SymbolTableFilterModel::setDisassembler(REDasm::Disassembler *disassembler)
{
    static_cast<SymbolTableModel*>(this->sourceModel())->setDisassembler(disassembler);
}

void SymbolTableFilterModel::setFilterName(const QString &name)
{
    this->_filtername = name;
    this->invalidateFilter();
}

void SymbolTableFilterModel::setFilterSymbol(u32 flags)
{
    this->_filtersymbol = flags;
    this->invalidateFilter();
}

bool SymbolTableFilterModel::filterAcceptsRow(int source_row, const QModelIndex &) const
{
    if(this->_filtersymbol == REDasm::SymbolTypes::None)
        return true;

    QModelIndex index = this->sourceModel()->index(source_row, 1);
    const REDasm::Symbol* symbol = reinterpret_cast<const REDasm::Symbol*>(index.internalPointer());
    bool res = (symbol->type & this->_filtersymbol);

    if(!this->_filtername.isEmpty())
    {
        if(this->_filtersymbol == REDasm::SymbolTypes::StringMask)
            res &= this->sourceModel()->data(index).toString().indexOf(this->_filtername, 0, Qt::CaseInsensitive) != -1;
        else
            res &= QString::fromStdString(symbol->name).indexOf(this->_filtername, 0, Qt::CaseInsensitive) != -1;
    }

    return res;
}
