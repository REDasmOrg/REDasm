#include "referencesmodel.h"
#include "../themeprovider.h"
#include <array>

ReferencesModel::ReferencesModel(const ICommand* command, QObject *parent): ContextModel(parent), m_command(command) { }

void ReferencesModel::clear()
{
    this->beginResetModel();
    m_referencescount = 0;
    m_references = nullptr;
    this->endResetModel();
}

void ReferencesModel::xref(rd_address address)
{
    if(!m_context || RDContext_IsBusy(m_context.get())) return;

    this->beginResetModel();
    const RDNet* net = RDContext_GetNet(m_context.get());
    m_referencescount = RDNet_GetReferences(net, address, &m_references);

    this->endResetModel();
}

QModelIndex ReferencesModel::index(int row, int column, const QModelIndex&) const
{
    if(row >= static_cast<int>(m_referencescount)) return QModelIndex();

    return this->createIndex(row, column, m_references[row]);
}

QVariant ReferencesModel::data(const QModelIndex &index, int role) const
{
    static std::array<rd_type, 3> TYPES = { DocumentItemType_Instruction,
                                            DocumentItemType_Symbol,
                                            DocumentItemType_None };

    if(!m_context || RDContext_IsBusy(m_context.get())) return QVariant();

    RDDocument* doc = RDContext_GetDocument(m_context.get());
    RDDocumentItem item;

    if(!RDDocument_GetAny(doc, m_references[index.row()], TYPES.data(), &item))
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return RD_ToHexAuto(item.address);
        else if(index.column() == 1) return this->direction(item.address);
        else if(index.column() == 2)
        {
            if(IS_TYPE(&item, DocumentItemType_Instruction)) return RD_GetInstruction(m_context.get(), item.address);
            else if(IS_TYPE(&item, DocumentItemType_Symbol)) return RDDocument_GetSymbolName(doc, item.address);
        }
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0) return THEME_VALUE(Theme_Address);

        if(index.column() == 2)
        {
            if(IS_TYPE(&item, DocumentItemType_Instruction))
            {
                const RDNet* net = RDContext_GetNet(m_context.get());
                const RDNetNode* node = RDNet_FindNode(net, item.address);
                if(!node) return QVariant();

                if(RDNetNode_IsConditional(node)) return THEME_VALUE(Theme_JumpCond);
                if(RDNetNode_IsBranch(node)) return THEME_VALUE(Theme_Jump);
                if(RDNetNode_IsCall(node)) return THEME_VALUE(Theme_Call);
            }
            else if(IS_TYPE(&item, DocumentItemType_Symbol))
            {
                RDSymbol symbol;
                if(!RDDocument_GetSymbolByAddress(doc, item.address, &symbol)) return QVariant();
                if(IS_TYPE(&symbol, SymbolType_Data)) return THEME_VALUE(Theme_Data);
                else if(IS_TYPE(&symbol, SymbolType_String)) return THEME_VALUE(Theme_String);
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

int ReferencesModel::rowCount(const QModelIndex &) const { return m_referencescount; }
int ReferencesModel::columnCount(const QModelIndex &) const { return 3; }

QString ReferencesModel::direction(rd_address address) const
{
    if(!m_command) return QString();

    RDDocumentItem item;
    if(!m_command->getCurrentItem(&item)) return QString();

    if(address > item.address) return "Down";
    if(address < item.address) return "Up";
    return "---";
}
