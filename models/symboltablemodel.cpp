#include "symboltablemodel.h"
#include <QFontDatabase>
#include <QColor>

SymbolTableModel::SymbolTableModel(QObject *parent) : DisassemblerModel(parent), _symboltable(NULL), _symbolflags(REDasm::SymbolTypes::None)
{

}

void SymbolTableModel::setDisassembler(REDasm::Disassembler *disassembler)
{
    DisassemblerModel::setDisassembler(disassembler);
    this->_symboltable = disassembler->symbolTable();
    this->loadSymbols();
}

void SymbolTableModel::setSymbolFlags(u32 symbolflags)
{
    this->_symbolflags = symbolflags;
    this->loadSymbols();
}

void SymbolTableModel::loadSymbols()
{
    if(!this->_symboltable || (this->_symbolflags == REDasm::SymbolTypes::None))
        return;

    this->beginResetModel();
    this->_symbols.clear();

    this->_symboltable->iterate(this->_symbolflags, [this](const REDasm::SymbolPtr& symbol) -> bool {
        this->_symbols << symbol;
        return true;
    });

    this->endResetModel();
}

QModelIndex SymbolTableModel::index(int row, int column, const QModelIndex &) const
{
    return this->createIndex(row, column, this->_symbols.at(row).get());
}

QVariant SymbolTableModel::data(const QModelIndex &index, int role) const
{
    if(!this->_disassembler || !this->_symboltable || !index.isValid())
        return QVariant();

    const REDasm::SymbolPtr& symbol = this->_symbols.at(index.row());

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(symbol->address, this->_disassembler->format()->bits()));

        if(index.column() == 1)
        {
            if(symbol->is(REDasm::SymbolTypes::WideStringMask))
                return QString::fromStdString(REDasm::quoted(this->_disassembler->readWString(symbol)));
            else if(symbol->is(REDasm::SymbolTypes::StringMask))
                return QString::fromStdString(REDasm::quoted(this->_disassembler->readString(symbol)));

            return QString::fromStdString(symbol->name);
        }

        if(index.column() == 2)
        {
            const REDasm::Segment* segment = this->_disassembler->format()->segment(symbol->address);

            if(segment)
                return S_TO_QS(segment->name);
        }
    }
    else if(role == Qt::BackgroundRole)
    {
        if(symbol->isFunction() && symbol->is(REDasm::SymbolTypes::Locked))
            return QColor::fromRgb(0xE2, 0xFF, 0xFF);
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0)
            return QColor(Qt::darkBlue);

        if(symbol->is(REDasm::SymbolTypes::String) && (index.column() == 1))
            return QColor(Qt::darkGreen);
    }
    else if(role == Qt::FontRole && index.column() == 0)
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);

    return QVariant();
}

QVariant SymbolTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return QVariant();

    if(section == 0)
        return "Address";
    else if(section == 1)
        return "Symbol";
    else if(section == 2)
        return "Segment";

    return QVariant();
}

int SymbolTableModel::rowCount(const QModelIndex&) const
{
    return this->_symbols.length();
}

int SymbolTableModel::columnCount(const QModelIndex&) const
{
    return 3;
}
