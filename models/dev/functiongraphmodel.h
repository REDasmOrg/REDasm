#pragma once

#include <QAbstractListModel>
#include <redasm/disassembler/disassembler.h>
#include <redasm/disassembler/model/functiongraph.h>

class FunctionGraphModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit FunctionGraphModel(QObject *parent = nullptr);
        void setGraph(const REDasm::FunctionGraph* graph);

    public:
        QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
        int columnCount(const QModelIndex &parent = QModelIndex()) const override;
        int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    private:
        const REDasm::FunctionGraph* m_graph{nullptr};

};

