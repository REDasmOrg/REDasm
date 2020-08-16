#include "functionlistmodel.h"
#include "../../themeprovider.h"

FunctionListModel::FunctionListModel(QObject *parent) : ListingItemModel(DocumentItemType_Function, parent) { }

const RDGraph* FunctionListModel::graph(const QModelIndex& index) const
{
    const RDDocumentItem& item = this->item(index);
    RDGraph* graph = nullptr;

    if(!RDDocument_GetFunctionGraph(m_document, item.address, &graph)) return nullptr;
    return graph;
}

QVariant FunctionListModel::data(const QModelIndex& index, int role) const
{
    if((role == Qt::ForegroundRole) && (index.column() == 1))
    {
        const RDDocumentItem& item = this->item(index);

        if(!RDDocument_GetFunctionGraph(m_document, item.address, nullptr))
            return THEME_VALUE(Theme_GraphEdgeFalse);
    }

    return ListingItemModel::data(index, role);
}
