#include "blocklistmodel.h"
#include <redasm/context.h>
#include <redasm/disassembler/disassembler.h>
#include "../../themeprovider.h"
#include "../../convert.h"

BlockListModel::BlockListModel(QObject *parent) : QAbstractListModel(parent) { }

QVariant BlockListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(role != Qt::DisplayRole) return QVariant();

    if(orientation == Qt::Horizontal)
    {
        switch(section)
        {
            case 0: return "Start Address";
            case 1: return "End Address";
            case 2: return "Size";
            case 3: return "Type";
            case 4: return "Symbol";
            default: break;
        }
    }
    else
        return this->segmentName(section);

    return QVariant();
}

QVariant BlockListModel::data(const QModelIndex& index, int role) const
{
    if(role == Qt::DisplayRole)
    {
        const REDasm::BlockItem* bi = r_docnew->blocks()->at(index.row());

        switch(index.column())
        {
            case 0: return Convert::to_qstring(REDasm::String::hex(bi->start));
            case 1: return Convert::to_qstring(REDasm::String::hex(bi->end));
            case 2: return Convert::to_qstring(REDasm::String::hex(bi->size()));
            case 3: return Convert::to_qstring(bi->displayType());
            case 4: return this->symbolName(index);
            default: break;
        }
    }
    else if(role == Qt::TextAlignmentRole) return Qt::AlignCenter;
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() < 3)  return THEME_VALUE("address_list_fg");
        if(index.column() == 3) return THEME_VALUE("type_fg");
        if(index.column() == 4) return THEME_VALUE("label_fg");
    }

    return QVariant();
}

int BlockListModel::columnCount(const QModelIndex&) const { return 5; }
int BlockListModel::rowCount(const QModelIndex&) const { return r_docnew->blocksCount(); }

QString BlockListModel::symbolName(const QModelIndex& index) const
{
    const REDasm::BlockItem* bi = r_docnew->blocks()->at(index.row());
    const REDasm::Symbol* symbol = r_docnew->symbol(bi->start);
    if(symbol) return Convert::to_qstring(symbol->name);
    return QString();
}

QString BlockListModel::segmentName(int section) const
{
    const REDasm::BlockItem* bi = r_docnew->blocks()->at(section);
    const REDasm::Segment* segment = r_docnew->segment(bi->start);
    if(segment) return Convert::to_qstring(segment->name);
    return QString();
}
