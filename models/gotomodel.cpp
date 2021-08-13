#include "gotomodel.h"
#include "../themeprovider.h"

GotoModel::GotoModel(const RDContextPtr& ctx, QObject *parent) : AddressModel(ctx, parent) { }

rd_address GotoModel::address(const QModelIndex& index) const
{
    const rd_address* addresses = nullptr;
    size_t c = RDDocument_GetLabels(m_document, &addresses);
    return (static_cast<size_t>(index.row()) < c) ? addresses[index.row()] : RD_NVAL;
}

QVariant GotoModel::data(const QModelIndex &index, int role) const
{
    if(!m_context) return QVariant();

    rd_address address = this->address(index);

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return RD_ToHexAuto(m_context.get(), address);

        if(index.column() == 1)
        {
            const char* label = RDDocument_GetLabel(m_document, address);
            return label ? label : QString();
        }
    }
    else if(role == Qt::TextAlignmentRole)
    {
        if(index.column() == 0) return Qt::AlignRight + Qt::AlignVCenter;
        if(index.column() == 1) return Qt::AlignLeft + Qt::AlignVCenter;
    }
    else if((role == Qt::ForegroundRole) && (index.column() == 0))
        return THEME_VALUE(Theme_Address);

    return QVariant();
}

QVariant GotoModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(section == 0)      return tr("Address");
        else if(section == 1) return tr("Name");
    }

    return ContextModel::headerData(section, orientation, role);
}

int GotoModel::columnCount(const QModelIndex &) const { return 2; }
int GotoModel::rowCount(const QModelIndex&) const { return RDDocument_GetLabels(m_document, nullptr); }
