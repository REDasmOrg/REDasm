#include "functiongraphmodel.h"
#include "../../themeprovider.h"

FunctionGraphModel::FunctionGraphModel(RDDisassembler* disassembler, QObject *parent) : QAbstractListModel(parent), m_disassembler(disassembler)
{
    m_document = RDDisassembler_GetDocument(disassembler);
}

void FunctionGraphModel::setGraph(const RDGraph* graph)
{
    this->beginResetModel();
    m_graph = graph;
    this->endResetModel();
}

QVariant FunctionGraphModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if((orientation != Qt::Horizontal) || (role != Qt::DisplayRole)) return QVariant();

    switch(section)
    {
        case 0: return "Start";
        case 1: return "End";
        case 2: return "Incoming";
        case 3: return "Outgoing";
        case 4: return "Symbol";
        default: break;
    }

    return QVariant();
}

QVariant FunctionGraphModel::data(const QModelIndex& index, int role) const
{
    if(!m_graph) return QVariant();

    if((role == Qt::UserRole) && (index.column() == 0))
    {
        const RDFunctionBasicBlock* fbb = nullptr;
        auto node = this->getBasicBlock(index, &fbb);
        if(!node) return QVariant();

        RDDocumentItem startitem;
        if(RDFunctionBasicBlock_GetStartItem(fbb, &startitem)) return QVariant::fromValue(startitem.address);
        return QVariant();
    }

    if(role == Qt::DisplayRole)
    {
        const RDFunctionBasicBlock* fbb = nullptr;
        auto node = this->getBasicBlock(index, &fbb);
        if(!node) return QVariant();

        RDDocumentItem startitem, enditem;

        if(!RDFunctionBasicBlock_GetStartItem(fbb, &startitem) || !RDFunctionBasicBlock_GetEndItem(fbb, &enditem))
            return QVariant();

        const char* symbolname = RDDocument_GetSymbolName(m_document, startitem.address);

        switch(index.column())
        {
            case 0: return RD_ToHexAuto(startitem.address);
            case 1: return RD_ToHexAuto(enditem.address);
            case 2: return QString::number(RDGraph_GetIncoming(m_graph, *node, nullptr));
            case 3: return QString::number(RDGraph_GetOutgoing(m_graph, *node, nullptr));
            case 4: return symbolname ? symbolname : QString();
            default: break;
        }
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() < 2) return THEME_VALUE("address_list_fg");
        else if(index.column() == 4) return THEME_VALUE("label_fg");
    }

    return QVariant();
}

int FunctionGraphModel::columnCount(const QModelIndex&) const { return 5; }
int FunctionGraphModel::rowCount(const QModelIndex&) const { return m_graph ? RDGraph_GetNodes(m_graph, nullptr) : 0; }

std::optional<RDGraphNode> FunctionGraphModel::getBasicBlock(const QModelIndex& index, const RDFunctionBasicBlock** fbb) const
{
    const RDGraphNode* nodes = nullptr;
    size_t c = RDGraph_GetNodes(m_graph, &nodes);
    if(static_cast<size_t>(index.row()) >= c) return std::nullopt;

    if(!RDFunctionGraph_GetBasicBlock(m_graph, nodes[index.row()], fbb)) return std::nullopt;
    return nodes[index.row()];
}
