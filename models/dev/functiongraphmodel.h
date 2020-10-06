#pragma once

#include <QAbstractListModel>
#include <rdapi/graph/functiongraph.h>
#include <rdapi/rdapi.h>
#include <optional>
#include "../hooks/idisassemblercommand.h"

class FunctionGraphModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit FunctionGraphModel(const RDContextPtr& ctx, QObject *parent = nullptr);
        void setGraph(const RDGraph* graph);

    public:
        QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
        int columnCount(const QModelIndex&) const override;
        int rowCount(const QModelIndex&) const override;

    private:
        std::optional<RDGraphNode> getBasicBlock(const QModelIndex& index, const RDFunctionBasicBlock** fbb) const;
        QString incomings(RDGraphNode node) const;
        QString outgoings(RDGraphNode node) const;

    private:
        RDContextPtr m_context;
        RDDocument* m_document;
        const RDGraph* m_graph{nullptr};

};

