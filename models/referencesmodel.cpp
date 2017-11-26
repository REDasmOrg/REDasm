#include "referencesmodel.h"
#include <QFontDatabase>
#include <QColor>

ReferencesModel::ReferencesModel(REDasm::Disassembler* disassembler, QObject *parent) : DisassemblerModel(parent), _currentaddress(0)
{
    this->setDisassembler(disassembler);
}

void ReferencesModel::xref(address_t currentaddress, REDasm::Symbol* symbol)
{
    this->beginResetModel();
    this->_currentaddress = currentaddress;
    this->_referencevector = this->_disassembler->getReferences(symbol);
    this->endResetModel();
}

QModelIndex ReferencesModel::index(int row, int column, const QModelIndex &) const
{
    return this->createIndex(row, column, this->_referencevector[row].get());
}

QVariant ReferencesModel::data(const QModelIndex &index, int role) const
{
    if(!this->_disassembler)
        return QVariant();

    const REDasm::InstructionPtr& instruction = this->_referencevector[index.row()];

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(instruction->address, this->_disassembler->format()->bits()));
        else if(index.column() == 1)
            return this->direction(instruction);
        else if(index.column() == 2)
            return S_TO_QS(this->_disassembler->out(instruction));
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
