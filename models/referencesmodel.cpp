#include "referencesmodel.h"
#include <QFontDatabase>
#include <QColor>

ReferencesModel::ReferencesModel(QObject *parent): DisassemblerModel(parent), _currentaddress(0)
{

}

void ReferencesModel::setDisassembler(REDasm::Disassembler *disassembler)
{
    DisassemblerModel::setDisassembler(disassembler);
    this->_printer = REDasm::PrinterPtr(disassembler->assembler()->createPrinter(disassembler, disassembler->symbolTable()));
}

void ReferencesModel::clear()
{
    this->beginResetModel();
    this->_referencevector.clear();
    this->endResetModel();
}

void ReferencesModel::xref(address_t currentaddress, const REDasm::SymbolPtr& symbol)
{
    if(!this->_disassembler)
        return;

    if(!symbol)
    {
        this->clear();
        return;
    }

    this->beginResetModel();
    this->_currentaddress = currentaddress;
    this->_referencevector = this->_disassembler->getReferences(symbol);
    this->endResetModel();
}

QModelIndex ReferencesModel::index(int row, int column, const QModelIndex &) const
{
    return this->createIndex(row, column, this->_referencevector[row]);
}

QVariant ReferencesModel::data(const QModelIndex &index, int role) const
{
    if(!this->_disassembler)
        return QVariant();

    REDasm::Listing& listing = this->_disassembler->listing();
    REDasm::InstructionPtr instruction = listing[this->_referencevector[index.row()]];

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(instruction->address, this->_disassembler->format()->bits()));
        else if(index.column() == 1)
            return this->direction(instruction);
        else if(index.column() == 2)
            return S_TO_QS(this->_printer->out(instruction));
    }
    else if(role == Qt::BackgroundRole)
    {
        if(!instruction->is(REDasm::InstructionTypes::Conditional))
            return QVariant();

        if(instruction->is(REDasm::InstructionTypes::Jump))
            return QColor("#ef717a");
        else if(instruction->is(REDasm::InstructionTypes::Call))
            return QColor("#a5c63b");
    }
    else if((role == Qt::ForegroundRole) && (index.column() == 0))
        return QColor(Qt::darkBlue);
    else if((role == Qt::FontRole) && (index.column() != 1))
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);
    else if((role == Qt::TextAlignmentRole) && (index.column() > 0))
        return Qt::AlignCenter;

    return QVariant();
}

QVariant ReferencesModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return QVariant();

    if(section == 0)
        return "Address";
    else if(section == 1)
        return "Direction";
    else if(section == 2)
        return "Instruction";

    return QVariant();
}

int ReferencesModel::rowCount(const QModelIndex &) const
{
    return this->_referencevector.size();
}

int ReferencesModel::columnCount(const QModelIndex &) const
{
    return 3;
}

QString ReferencesModel::direction(const REDasm::InstructionPtr &instruction) const
{
    if(instruction->address > this->_currentaddress)
        return "Down";

    if(instruction->address < this->_currentaddress)
        return "Up";

    return "---";
}
