#include "functionlistmodel.h"
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/disassembler/disassembler.h>
#include <redasm/context.h>
#include "themeprovider.h"
#include "convert.h"

FunctionListModel::FunctionListModel(QObject *parent) : QAbstractListModel(parent) { }

QVariant FunctionListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if((orientation != Qt::Horizontal) || (role != Qt::DisplayRole)) return QVariant();

    if(section == 0) return "Address";
    if(section == 1) return "Name";
    return QVariant();
}

QVariant FunctionListModel::data(const QModelIndex& index, int role) const
{
    if(role == Qt::DisplayRole)
    {
        address_t address = r_doc->functionAt(index.row());

        if(index.column() == 0)
            return Convert::to_qstring(REDasm::String::hex(address, r_asm->bits()));

        if(index.column() == 1)
        {
            auto* symbol = r_doc->symbol(address);
            return symbol ? Convert::to_qstring(symbol->name) : "";
        }

    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0) return THEME_VALUE("address_list_fg");

        address_t address = r_doc->functionAt(index.row());
        if(!r_doc->graph(address)) return THEME_VALUE("graph_edge_false");
    }

    return QVariant();
}

int FunctionListModel::columnCount(const QModelIndex& parent) const { return 2; }
int FunctionListModel::rowCount(const QModelIndex& parent) const { return r_doc->functions()->size(); }
