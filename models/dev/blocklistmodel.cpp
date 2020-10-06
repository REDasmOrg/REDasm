#include "blocklistmodel.h"
#include "../../themeprovider.h"

BlockListModel::BlockListModel(ICommand* command, const RDBlockContainer* blocks, QObject *parent) : QAbstractListModel(parent), m_blocks(blocks), m_command(command)
{
    m_document = RDContext_GetDocument(command->context().get());
}

QVariant BlockListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(role != Qt::DisplayRole) return QVariant();
    if(orientation != Qt::Horizontal) return QVariant();

    switch(section)
    {
        case 0: return "Start Address";
        case 1: return "End Address";
        case 2: return "Size";
        case 3: return "Type";
        case 4: return "Symbol";
        default: break;
    }

    return QVariant();
}

QVariant BlockListModel::data(const QModelIndex& index, int role) const
{
    if(!m_blocks) return QVariant();

    if(role == Qt::DisplayRole)
    {
        RDBlock block;
        if(!RDBlockContainer_Get(m_blocks, index.row(), &block)) return QVariant();

        switch(index.column())
        {
            case 0: return RD_ToHexAuto(block.start);
            case 1: return RD_ToHexAuto(block.end);
            case 2: return RD_ToHexAuto(RDBlock_Size(&block));
            case 3: return this->blockType(&block);
            case 4: return this->symbolName(&block);
            default: break;
        }
    }
    else if(role == Qt::TextAlignmentRole) return Qt::AlignCenter;
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() < 3)  return THEME_VALUE(Theme_Address);
        if(index.column() == 3) return THEME_VALUE(Theme_Type);
        if(index.column() == 4) return THEME_VALUE(Theme_Symbol);
    }

    return QVariant();
}

int BlockListModel::columnCount(const QModelIndex&) const { return 5; }
int BlockListModel::rowCount(const QModelIndex&) const { return m_blocks ? static_cast<int>(RDBlockContainer_Size(m_blocks)) : 0; }

QString BlockListModel::blockType(const RDBlock* block) const
{
    switch(block->type)
    {
        case BlockType_Code:       return "CODE";
        case BlockType_Data:       return "DATA";
        case BlockType_Unexplored: return "UNEXPLORED";
        default: break;
    }

    return QString();
}

QString BlockListModel::symbolName(const RDBlock* block) const
{
    const char* name = RDDocument_GetSymbolName(m_document, block->address);
    return name ? name : QString();
}
