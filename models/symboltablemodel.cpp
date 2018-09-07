#include "symboltablemodel.h"
#include "../../redasm/disassembler/listing/listingdocument.h"
#include "../../redasm/plugins/format.h"
#include <QFontDatabase>
#include <QColor>

SymbolTableModel::SymbolTableModel(QObject *parent) : DisassemblerModel(parent), m_symboltable(NULL), m_symbolflags(REDasm::SymbolTypes::None)
{

}

void SymbolTableModel::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    DisassemblerModel::setDisassembler(disassembler);
    m_symboltable = disassembler->document()->symbols();
    this->loadSymbols();
}

void SymbolTableModel::setSymbolFlags(u32 symbolflags)
{
    m_symbolflags = symbolflags;
    this->loadSymbols();
}

void SymbolTableModel::loadSymbols()
{
    if(!m_symboltable || (this->m_symbolflags == REDasm::SymbolTypes::None))
        return;

    this->beginResetModel();
    m_symbols.clear();

    m_symboltable->iterate(this->m_symbolflags, [this](const REDasm::SymbolPtr& symbol) -> bool {
        m_symbols << symbol;
        return true;
    });

    this->endResetModel();
}

QModelIndex SymbolTableModel::index(int row, int column, const QModelIndex &) const
{
    return this->createIndex(row, column, this->m_symbols.at(row).get());
}

QVariant SymbolTableModel::data(const QModelIndex &index, int role) const
{
    if(!this->m_disassembler || !m_symboltable || !index.isValid())
        return QVariant();

    const REDasm::SymbolPtr& symbol = m_symbols.at(index.row());

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(symbol->address, m_disassembler->format()->bits(), false));

        if(index.column() == 1)
        {
            if(symbol->is(REDasm::SymbolTypes::WideStringMask))
                return QString::fromStdString(REDasm::quoted(m_disassembler->readWString(symbol)));
            else if(symbol->is(REDasm::SymbolTypes::StringMask))
                return QString::fromStdString(REDasm::quoted(m_disassembler->readString(symbol)));

            return QString::fromStdString(symbol->name);
        }

        if(index.column() == 2)
            return QString::number(m_disassembler->getReferencesCount(symbol->address));

        if(index.column() == 3)
        {
            const REDasm::Segment* segment = m_disassembler->document()->segment(symbol->address);

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
        if((index.column() == 0) || (index.column() == 2))
            return QColor(Qt::darkBlue);

        if(symbol->is(REDasm::SymbolTypes::String) && (index.column() == 1))
            return QColor(Qt::darkGreen);
    }
    else if((role == Qt::TextAlignmentRole) && (index.column() > 1))
        return Qt::AlignCenter;
    else if((role == Qt::FontRole) && (index.column() == 0))
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);

    return QVariant();
}

QVariant SymbolTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(section == 0)
            return "Address";
        else if(section == 1)
            return "Symbol";
        else if(section == 2)
            return "R";
        else if(section == 3)
            return "Segment";
    }
    else if(role == Qt::TextAlignmentRole)
        return Qt::AlignCenter;

    return QVariant();
}

int SymbolTableModel::rowCount(const QModelIndex&) const { return m_symbols.length(); }
int SymbolTableModel::columnCount(const QModelIndex&) const { return 4; }
