#include "rdilmodel.h"
#include "../themeprovider.h"

RDILModel::RDILModel(IDisassemblerCommand* command, QObject *parent) : QAbstractListModel(parent)
{
    RDDocumentItem item;
    if(!command->getCurrentItem(&item)) return;

    m_renderer.reset(RDRenderer_Create(command->disassembler(), nullptr, RendererFlags_Simplified));

    RDIL_Disassemble(command->disassembler(), item.address, [](const RDILDisassembled* d, void* userdata) {
        auto* thethis = reinterpret_cast<RDILModel*>(userdata);
        if(!d->index) thethis->m_items.push_back({ *d, RDRenderer_GetInstruction(thethis->m_renderer.get(), d->address) });
        else thethis->m_items.push_back({ *d, QString() });
    }, this);
}

QVariant RDILModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(role != Qt::DisplayRole) return QVariant();

    if(orientation == Qt::Horizontal)
    {
        switch(section)
        {
            case 0: return "Instruction";
            case 1: return "Result";
            default: break;
        }
    }
    else
    {
        auto& d = m_items[section];
        return QString::fromStdString(rd_tohex(d.first.address) + "/" + std::to_string(d.first.index));
    }

    return QVariant();
}

QVariant RDILModel::data(const QModelIndex& index, int role) const
{
    auto& d = m_items[index.row()];

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return d.second;
        if(index.column() == 1) return d.first.result;
    }
    else if((role == Qt::BackgroundRole) && (index.column() == 1))
    {
        if(d.first.rdil.id == RDIL_Unknown)
            return THEME_VALUE("instruction_invalid");
    }

    return QVariant();
}

int RDILModel::columnCount(const QModelIndex&) const { return 2; }
int RDILModel::rowCount(const QModelIndex&) const { return m_items.size(); }
