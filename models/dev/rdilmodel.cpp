#include "rdilmodel.h"
#include "../themeprovider.h"

RDILModel::RDILModel(IDisassemblerCommand* command, QObject *parent) : QAbstractListModel(parent), m_command(command)
{
    m_renderer.reset(RDRenderer_Create(command->disassembler(), nullptr, RendererFlags_Simplified));
    this->update();
}

QVariant RDILModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(role != Qt::DisplayRole) return QVariant();

    // if(orientation == Qt::Horizontal)
    // {
    //     switch(section)
    //     {
    //         case 0: return "Instruction";
    //         case 1: return "Result";
    //         default: break;
    //     }
    // }
    // else
    // {
    //     auto& d = m_items[section];
    //     return QString::fromStdString(rd_tohex(d.first.address) + "/" + std::to_string(d.first.index));
    // }

    return QVariant();
}

QVariant RDILModel::data(const QModelIndex& index, int role) const
{
    // auto& d = m_items[index.row()];

    // if(role == Qt::DisplayRole)
    // {
    //     if(index.column() == 0) return d.second;
    //     if(index.column() == 1) return d.first.result;
    // }
    // else if((role == Qt::BackgroundRole) && (index.column() == 1))
    // {
    //     //FIXME: //if(d.first.rdil.id == RDIL_Unknown)
    //         //FIXME: return THEME_VALUE("instruction_invalid");
    // }

    return QVariant();
}

int RDILModel::columnCount(const QModelIndex&) const { return 2; }
int RDILModel::rowCount(const QModelIndex&) const { return 0; }

void RDILModel::update()
{
    // this->beginResetModel();
    //
    // m_items.clear();

    // RDDocumentItem item;
    // if(!m_command->getCurrentItem(&item)) return;

    // RDIL_Disassemble(m_command->disassembler(), item.address, [](const RDILDisassembled* d, void* userdata) {
    //     auto* thethis = reinterpret_cast<RDILModel*>(userdata);
    //     if(!d->index) thethis->m_items.push_back({ *d, RDRenderer_GetInstructionText(thethis->m_renderer.get(), d->address) });
    //     else thethis->m_items.push_back({ *d, QString() });
    // }, this);
    //
    // this->endResetModel();
}
