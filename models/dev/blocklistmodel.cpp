#include "blocklistmodel.h"
#include "../../themeprovider.h"

BlockListModel::BlockListModel(const RDContextPtr& ctx, const RDBlockContainer* blocks, QObject *parent) : QAbstractListModel(parent), m_blockcontainer(blocks), m_context(ctx)
{
    m_document = RDContext_GetDocument(ctx.get());

    RDBlockContainer_Each(blocks, [](const RDBlock* b, void* userdata) {
       auto* thethis = reinterpret_cast<BlockListModel*>(userdata);
       thethis->m_blocks.push_back(*b);
       return true;
    }, this);
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
    if(!m_blockcontainer) return QVariant();

    if(role == Qt::DisplayRole)
    {
        const RDBlock& block = m_blocks[index.row()];

        switch(index.column())
        {
            case 0: return RD_ToHexAuto(m_context.get(), block.start);
            case 1: return RD_ToHexAuto(m_context.get(), block.end);
            case 2: return RD_ToHexAuto(m_context.get(), RDBlock_Size(&block));
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
int BlockListModel::rowCount(const QModelIndex&) const { return m_blocks.size(); }

QString BlockListModel::blockType(const RDBlock* block) const
{
    switch(block->type)
    {
        case BlockType_Code:    return "CODE";
        case BlockType_Data:    return "DATA";
        case BlockType_Unknown: return "UNKNOWN";
        default: break;
    }

    return QString();
}

QString BlockListModel::symbolName(const RDBlock* block) const
{
    const char* name = RDDocument_GetSymbolName(m_document, block->address);
    return name ? name : QString();
}
