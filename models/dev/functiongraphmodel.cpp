#include "functiongraphmodel.h"
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/disassembler/disassembler.h>
#include <redasm/context.h>
#include "themeprovider.h"
#include "convert.h"

FunctionGraphModel::FunctionGraphModel(QObject *parent) : QAbstractListModel(parent) { }

void FunctionGraphModel::setGraph(const REDasm::FunctionGraph* graph)
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

    if(role == Qt::DisplayRole)
    {
        auto n = m_graph->nodes().at(index.row());
        const auto* fbb = variant_object<REDasm::FunctionBasicBlock>(m_graph->data(n));
        const auto& startitem = fbb->startItem();
        const auto& enditem = fbb->endItem();
        const auto* symbol = r_doc->symbol(startitem.address);

        switch(index.column())
        {
            case 0: return Convert::to_qstring(REDasm::String::hex(startitem.address, r_asm->bits()));
            case 1: return Convert::to_qstring(REDasm::String::hex(enditem.address, r_asm->bits()));
            case 2: return QString::number(m_graph->incoming(n).size());
            case 3: return QString::number(m_graph->outgoing(n).size());
            case 4: return symbol ? Convert::to_qstring(symbol->name) : QString();
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

int FunctionGraphModel::columnCount(const QModelIndex& parent) const { return 5; }
int FunctionGraphModel::rowCount(const QModelIndex& parent) const { return m_graph ? m_graph->nodes().size() : 0; }
