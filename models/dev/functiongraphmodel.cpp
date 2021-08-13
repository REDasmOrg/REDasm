#include "functiongraphmodel.h"
#include "../../themeprovider.h"

FunctionGraphModel::FunctionGraphModel(const RDContextPtr& ctx, QObject *parent) : QAbstractListModel(parent), m_context(ctx)
{
    m_document = RDContext_GetDocument(ctx.get());
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
        case 0: return tr("Symbol");
        case 1: return tr("Start");
        case 2: return tr("End");
        case 3: return tr("Incoming");
        case 4: return tr("Outgoing");
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
        return node ? QVariant::fromValue(RDFunctionBasicBlock_GetStartAddress(fbb)) : QVariant();
    }

    if(role == Qt::DisplayRole)
    {
        const RDFunctionBasicBlock* fbb = nullptr;
        auto node = this->getBasicBlock(index, &fbb);
        if(!node) return QVariant();

        rd_address startaddress = RDFunctionBasicBlock_GetStartAddress(fbb);
        const char* label = RDDocument_GetLabel(m_document, startaddress);

        switch(index.column())
        {
            case 0: return label ? label : QString();
            case 1: return RD_ToHexAuto(m_context.get(), startaddress);
            case 2: return RD_ToHexAuto(m_context.get(), RDFunctionBasicBlock_GetEndAddress(fbb));
            case 3: return this->incomings(*node);
            case 4: return this->outgoings(*node);
            default: break;
        }
    }
    else if(role == Qt::ForegroundRole)
    {
        if((index.column() == 1) || (index.column() == 2)) return THEME_VALUE(Theme_Address);
        else if(index.column() == 0) return THEME_VALUE(Theme_Label);
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
