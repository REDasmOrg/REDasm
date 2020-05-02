#include "referencesmodel.h"
#include "../themeprovider.h"

ReferencesModel::ReferencesModel(const IDisassemblerCommand* command, QObject *parent): DisassemblerModel(parent), m_command(command) { }
ReferencesModel::~ReferencesModel() { if(m_renderer) RD_Free(m_renderer); }

void ReferencesModel::setDisassembler(RDDisassembler* disassembler)
{
    DisassemblerModel::setDisassembler(disassembler);
    m_renderer = RDRenderer_Create(m_disassembler, nullptr, RendererFlags_Simplified);
}

void ReferencesModel::clear()
{
    this->beginResetModel();
    m_referencescount = 0;
    m_references = nullptr;
    this->endResetModel();
}

void ReferencesModel::xref(address_t address)
{
    if(!m_disassembler || RD_IsBusy()) return;

    this->beginResetModel();
    m_referencescount = RDDisassembler_GetReferences(m_disassembler, address, &m_references);
    this->endResetModel();
}

QModelIndex ReferencesModel::index(int row, int column, const QModelIndex&) const
{
    if(row >= static_cast<int>(m_referencescount)) return QModelIndex();

    return this->createIndex(row, column, m_references[row]);
}

QVariant ReferencesModel::data(const QModelIndex &index, int role) const
{
    if(!m_disassembler || !m_renderer || RD_IsBusy()) return QVariant();

    RDDocument* doc = RDDisassembler_GetDocument(m_disassembler);
    RDDocumentItem item;

    if(!RDDocument_GetInstructionItem(doc, m_references[index.row()], &item))
    {
        if(!RDDocument_GetSymbolItem(doc, m_references[index.row()], &item))
            return QVariant();
    }

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return RD_ToHex(item.address);
        else if(index.column() == 1) return this->direction(doc, item.address);
        else if(index.column() == 2)
        {
            if(item.type == DocumentItemType_Instruction) return RDRenderer_GetInstruction(m_renderer, item.address);
            else if(item.type == DocumentItemType_Symbol) return RDDocument_GetSymbolName(doc, item.address);
        }
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0) return THEME_VALUE("address_fg");

        if(index.column() == 2)
        {
            if(item.type == DocumentItemType_Instruction)
            {
                InstructionLock instruction(doc, item.address);
                if(!instruction) return QVariant();

                if(instruction->flags & InstructionFlags_Conditional) return THEME_VALUE("instruction_jmp_c");
                else if(instruction->type == InstructionType_Jump) return THEME_VALUE("instruction_jmp");
                else if(instruction->type == InstructionType_Call) return THEME_VALUE("instruction_call");
            }
            else if(item.type == DocumentItemType_Symbol)
            {
                RDSymbol symbol;
                if(!RDDocument_GetSymbolByAddress(doc, item.address, &symbol)) return QVariant();
                if(symbol.type == SymbolType_Data) return THEME_VALUE("data_fg");
                else if(symbol.type == SymbolType_String) return THEME_VALUE("string_fg");
            }
        }
    }

    return QVariant();
}

QVariant ReferencesModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return QVariant();

    if(section == 0) return "Address";
    else if(section == 1) return "Direction";
    else if(section == 2) return "Reference";

    return QVariant();
}

int ReferencesModel::rowCount(const QModelIndex &) const { return static_cast<int>(m_referencescount); }
int ReferencesModel::columnCount(const QModelIndex &) const { return 3; }

QString ReferencesModel::direction(RDDocument* doc, address_t address) const
{
    if(!m_command) return QString();

    RDDocumentItem item;
    if(!RDDocument_GetItemAt(doc, m_command->currentPosition()->line, &item)) return QString();

    if(address > item.address) return "Down";
    if(address < item.address) return "Up";
    return "---";
}
