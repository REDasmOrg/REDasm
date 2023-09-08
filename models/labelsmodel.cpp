#include "labelsmodel.h"
#include "../themeprovider.h"

LabelsModel::LabelsModel(const RDContextPtr& ctx, rd_flag flag, QObject *parent) : AddressModel(ctx, parent), m_flag(flag) { }

rd_address LabelsModel::address(const QModelIndex& index) const
{
    const rd_address* addresses = nullptr;
    size_t c = RDDocument_GetLabelsByFlag(m_document, m_flag, &addresses);
    return (static_cast<size_t>(index.row()) < c) ? addresses[index.row()] : RD_NVAL;
}

int LabelsModel::rowCount(const QModelIndex&) const { return m_document ? RDDocument_GetLabelsByFlag(m_document, m_flag, nullptr) : 0; }
int LabelsModel::columnCount(const QModelIndex&) const { return 4; }

QVariant LabelsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical) return QVariant();

    if(role == Qt::DisplayRole)
    {
        switch(section)
        {
            case 0: return tr("Address");
            case 1: return tr("Segment");
            case 2: return tr("R");
            case 3: return tr("Label");
            default: break;
        }
    }

    return QVariant();
}

QVariant LabelsModel::data(const QModelIndex& index, int role) const
{
    if(!m_document) return QVariant();

    rd_address address = this->address(index);
    if(address == RD_NVAL) return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return RD_ToHexAuto(m_context.get(), address);

        if(index.column() == 1)
        {
            RDSegment segment;
            return RDDocument_AddressToSegment(m_document, address, &segment) ? segment.name : "???";
        }

        if(index.column() == 2)
        {
            const RDNet* net = RDContext_GetNet(m_context.get());
            return QString::number(RDNet_GetReferences(net, address, nullptr));
        }

        if(index.column() == 3)
        {
            const char* n = RDDocument_GetLabel(m_document, address);
            return n ? RD_Demangle(n) : QVariant();
        }
    }
    else if(role == Qt::ForegroundRole) return (index.column() == 0) ? THEME_VALUE(Theme_Address) : QVariant();
    else if(role == Qt::TextAlignmentRole) return QVariant{(index.column() < 3) ? (Qt::AlignCenter | Qt::AlignVCenter) : (Qt::AlignLeft | Qt::AlignVCenter)};

    return QVariant();
}

QString LabelsModel::escapeString(const QString& s)
{
    QString res;

    for(const QChar& ch : s)
    {
        switch(ch.toLatin1())
        {
            case '\n': res += R"(\n)"; break;
            case '\r': res += R"(\r)"; break;
            case '\t': res += R"(\t)"; break;
            default: res += ch; break;
        }
    }

    return res;
}
