#include "functionsmodel.h"
#include "../themeprovider.h"

FunctionsModel::FunctionsModel(const RDContextPtr& ctx, QObject* parent): AddressModel(ctx, parent) { }
QString FunctionsModel::function(const QModelIndex& index) const { return this->function(index, nullptr); }

rd_address FunctionsModel::address(const QModelIndex& index) const
{
    const rd_address* addresses = nullptr;
    size_t c = RDDocument_GetFunctions(m_document, &addresses);
    return (static_cast<size_t>(index.row()) < c) ? addresses[index.row()] : RD_NVAL;
}

QVariant FunctionsModel::data(const QModelIndex& index, int role) const
{
    if(!m_document) return QVariant();

    if(role == Qt::DisplayRole)
    {
        rd_address address = 0;
        QString n = this->function(index, &address);
        if(n.isEmpty()) return QVariant();

        if(index.column() == 0) return RD_ToHexAuto(m_context.get(), address);
        if(index.column() == 1) return n;
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

QVariant FunctionsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return QVariant();

    switch(section)
    {
        case 0: return "Address";
        case 1: return "Name";
        default: break;
    }

    return QVariant();
}

int FunctionsModel::columnCount(const QModelIndex&) const { return 2; }
int FunctionsModel::rowCount(const QModelIndex&) const { return m_document ? RDDocument_GetFunctions(m_document, nullptr) : 0; }

QString FunctionsModel::function(const QModelIndex& index, rd_address* address) const
{
    const rd_address* addresses = nullptr;
    if(static_cast<size_t>(index.row()) >= RDDocument_GetFunctions(m_document, &addresses)) return QString();
    if(address) *address = addresses[index.row()];

    const char* n = RDDocument_GetLabel(m_document, addresses[index.row()]);
    return n ? n : QString();
}
