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
        case 0: return "Symbol";
        case 1: return "Start";
        case 2: return "End";
        case 3: return "Incoming";
        case 4: return "Outgoing";
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
            case 0: return symbolname ? symbolname : QString();
            case 1: return RD_ToHexAuto(startitem.address);
            case 2: return RD_ToHexAuto(enditem.address);
            case 3: return this->incomings(*node);
            case 4: return this->outgoings(*node);
            default: break;
        }
    }
    else if(role == Qt::ForegroundRole)
    {
        if((index.column() == 1) || (index.column() == 2)) return THEME_VALUE("address_list_fg");
        else if(index.column() == 0) return THEME_VALUE("label_fg");
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

QString FunctionGraphModel::incomings(RDGraphNode node) const
{
    const RDGraphEdge* edges = nullptr;
    size_t c = RDGraph_GetIncoming(m_graph, node, &edges);

    QString s;

    for(size_t i = 0; i < c; i++)
    {
        const RDFunctionBasicBlock* fbb = nullptr;
        if(!RDFunctionGraph_GetBasicBlock(m_graph, edges[i].source, &fbb)) continue;
        if(!s.isEmpty()) s.append(", ");
        s.append(RD_ToHex(RDFunctionBasicBlock_GetStartAddress(fbb)));
    }

    return s;
}

QString FunctionGraphModel::outgoings(RDGraphNode node) const
{
    const RDGraphEdge* edges = nullptr;
    size_t c = RDGraph_GetOutgoing(m_graph, node, &edges);

    QString s;

    for(size_t i = 0; i < c; i++)
    {
        const RDFunctionBasicBlock* fbb = nullptr;
        if(!RDFunctionGraph_GetBasicBlock(m_graph, edges[i].target, &fbb)) continue;
        if(!s.isEmpty()) s.append(", ");
        s.append(RD_ToHex(RDFunctionBasicBlock_GetStartAddress(fbb)));
    }

    return s;
}
