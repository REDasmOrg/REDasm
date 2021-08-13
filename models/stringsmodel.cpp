#include "stringsmodel.h"
#include "../themeprovider.h"

StringsModel::StringsModel(const RDContextPtr& ctx, QObject* parent): LabelsModel(ctx, AddressFlags_String, parent) { }

QVariant StringsModel::data(const QModelIndex& index, int role) const
{
    if(!m_document) return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return RD_ToHexAuto(m_context.get(), this->address(index));
        if(index.column() == 1) return this->segment(index);
        if(index.column() == 2) return this->string(index);
    }
    else if(role == Qt::TextAlignmentRole)
    {
        if(index.column() == 0) return Qt::AlignRight + Qt::AlignVCenter;
        if(index.column() == 2) return Qt::AlignLeft + Qt::AlignVCenter;
        return Qt::AlignCenter;
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0) return THEME_VALUE(Theme_Address);
        if(index.column() == 2) return THEME_VALUE(Theme_String);
    }
    else if((role == Qt::ForegroundRole) && (index.column() == 0))
       return THEME_VALUE(Theme_Address);

    return QVariant();
}

QVariant StringsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return QVariant();

    switch(section)
    {
        case 0: return tr("Address");
        case 1: return tr("Segment");
        case 2: return tr("String");
        default: break;
    }

    return QVariant();
}

int StringsModel::columnCount(const QModelIndex&) const { return 3; }

QString StringsModel::segment(const QModelIndex& index) const
{
    rd_address address = this->address(index);
    if(address == RD_NVAL) return QString();

    RDSegment segment;
    if(!RDDocument_AddressToSegment(m_document, address, &segment)) return QString();
    return segment.name;
}

QString StringsModel::string(const QModelIndex& index) const
{
    rd_address address = this->address(index);
    if(address == RD_NVAL) return QString();

    RDBlock block;
    if(!RDDocument_AddressToBlock(m_document, address, &block)) return QString();

    auto flags = RDDocument_GetFlags(m_document, address);
    size_t len = RDBlock_Size(&block);

    if(flags & AddressFlags_WideString)
    {
        auto* wptr = RD_ReadWString(this->context().get(), address, &len);
        return wptr ? StringsModel::escapeString(QString::fromUtf16(wptr, len)) : QString();
    }

    auto* ptr = RD_ReadString(this->context().get(), address, &len);
    return ptr ? StringsModel::escapeString(QString::fromUtf8(ptr, len)) : QString();
}

QString StringsModel::escapeString(const QString& s)
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
