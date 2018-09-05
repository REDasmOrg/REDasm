#include "referencesmodel.h"
#include "../redasm/disassembler/types/referencetable.h"
#include "../themeprovider.h"
#include <QFontDatabase>

ReferencesModel::ReferencesModel(QObject *parent): DisassemblerModel(parent), _currentaddress(0), _instructionrefs(false)
{

}

void ReferencesModel::setDisassembler(REDasm::Disassembler *disassembler)
{
    DisassemblerModel::setDisassembler(disassembler);
    //this->_printer = REDasm::PrinterPtr(disassembler->assembler()->createPrinter(disassembler, disassembler->symbolTable()));
}

void ReferencesModel::xref(const REDasm::InstructionPtr& instruction)
{
    if(!this->m_disassembler)
        return;

    this->_instructionrefs = false;

    this->beginResetModel();
    this->_currentaddress = instruction->address;
    this->_references.clear();

    std::for_each(instruction->references.begin(), instruction->references.end(), [this](address_t ref) {
        this->_references.push_back(ref);
    });

    this->endResetModel();
}

void ReferencesModel::clear()
{
    this->beginResetModel();
    this->_references.clear();
    this->endResetModel();
}

QVariant ReferencesModel::dataInstructionRefs(const QModelIndex &index, int role) const
{
    /*
    REDasm::InstructionsPool& listing = this->_disassembler->instructions();
    REDasm::InstructionPtr instruction = listing[this->_references[index.row()]];

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
        {
            REDasm::SymbolPtr symbol = listing.getFunction(instruction->address);

            if(symbol)
            {
                address_t diff = instruction->address - symbol->address;

                if(diff)
                    return S_TO_QS(symbol->name + "+" + REDasm::hex(diff));
                else
                    return S_TO_QS(symbol->name);
            }

            return S_TO_QS(REDasm::hex(instruction->address, this->_disassembler->format()->bits()));
        }
        else if(index.column() == 1)
            return this->direction(instruction->address);
        else if(index.column() == 2)
            return S_TO_QS(this->_printer->out(instruction));
    }
    else if((role == Qt::ForegroundRole) && (index.column() == 2))
    {
        if(!instruction->is(REDasm::InstructionTypes::Conditional))
            return THEME_VALUE("instruction_jmp_c");
        else if(instruction->is(REDasm::InstructionTypes::Jump))
            return THEME_VALUE("instruction_jmp");
        else if(instruction->is(REDasm::InstructionTypes::Call))
            return THEME_VALUE("instruction_call");
    }
    */

    return QVariant();
}

QVariant ReferencesModel::dataSymbolRefs(const QModelIndex &index, int role) const
{
    /*
    REDasm::SymbolTable* symboltable = this->m_disassembler->symbolTable();
    REDasm::SymbolPtr symbol = symboltable->symbol(this->_references[index.row()]);

    if(!symbol)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(symbol->address, this->m_disassembler->format()->bits()));
        else if(index.column() == 1)
            return this->direction(symbol->address);
        else if(index.column() == 2)
            return S_TO_QS(this->_printer->symbol(symbol));
    }
    else if((role == Qt::ForegroundRole) && (index.column() == 2))
    {
        if(symbol->is(REDasm::SymbolTypes::Pointer))
            return QVariant();

        if(symbol->is(REDasm::SymbolTypes::Data))
            return THEME_VALUE("data_fg");
        else if(symbol->is(REDasm::SymbolTypes::String))
            return THEME_VALUE("string_fg");
    }
    */

    return QVariant();
}

void ReferencesModel::xref(address_t currentaddress, const REDasm::SymbolPtr& symbol)
{
    if(!this->m_disassembler)
        return;

    if(!symbol)
    {
        this->clear();
        return;
    }

    this->_instructionrefs = true;

    this->beginResetModel();
    this->_currentaddress = currentaddress;
    this->_references = this->m_disassembler->getReferences(symbol);
    this->endResetModel();
}

QModelIndex ReferencesModel::index(int row, int column, const QModelIndex &) const
{
    return this->createIndex(row, column, this->_references[row]);
}

QVariant ReferencesModel::data(const QModelIndex &index, int role) const
{
    if(!this->m_disassembler)
        return QVariant();

    if((role == Qt::ForegroundRole) && (index.column() == 0))
        return QColor(Qt::darkBlue);
    else if((role == Qt::FontRole) && (index.column() != 1))
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);
    else if((role == Qt::TextAlignmentRole) && (index.column() > 0))
        return Qt::AlignCenter;

    if(this->_instructionrefs)
        return this->dataInstructionRefs(index, role);

    return this->dataSymbolRefs(index, role);
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
    return this->_references.size();
}

int ReferencesModel::columnCount(const QModelIndex &) const
{
    return 3;
}

QString ReferencesModel::direction(address_t address) const
{
    if(address > this->_currentaddress)
        return "Down";

    if(address < this->_currentaddress)
        return "Up";

    return "---";
}
