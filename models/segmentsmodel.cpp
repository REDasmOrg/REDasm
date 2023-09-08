#include "segmentsmodel.h"
#include <QColor>
#include "../themeprovider.h"

#define ADD_SEGMENT_FLAG(s, t) { if(!s.isEmpty()) s += " | ";  s += t; }

SegmentsModel::SegmentsModel(const RDContextPtr& ctx, QObject *parent) : AddressModel(ctx, parent) { }

rd_address SegmentsModel::address(const QModelIndex& index) const
{
    const rd_address* addresses = nullptr;
    size_t c = RDDocument_GetSegments(m_document, &addresses);
    return (static_cast<size_t>(index.row()) < c) ? addresses[index.row()] : RD_NVAL;
}

QVariant SegmentsModel::data(const QModelIndex &index, int role) const
{
    if(!m_document) return QVariant();

    if(role == Qt::DisplayRole)
    {
        RDSegment segment;
        RDDocument_AddressToSegment(m_document, this->address(index), &segment);

        switch(index.column())
        {
            case 0: return QString::fromUtf8(segment.name);
            case 1: return QString::fromUtf8(RD_ToHexAuto(m_context.get(), segment.address));
            case 2: return QString::fromUtf8(RD_ToHexAuto(m_context.get(), segment.endaddress));
            case 3: return QString::fromUtf8(RD_ToHexAuto(m_context.get(), RDSegment_Size(&segment)));
            case 4: return QString::fromUtf8(RD_ToHexAuto(m_context.get(), segment.offset));
            case 5: return QString::fromUtf8(RD_ToHexAuto(m_context.get(), segment.endoffset));
            case 6: return QString::fromUtf8(RD_ToHexAuto(m_context.get(), RDSegment_RawSize(&segment)));
            case 7: return SegmentsModel::segmentFlags(segment);
            default: break;
        }
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0) return THEME_VALUE(Theme_Label);
        if(index.column() < 7) return THEME_VALUE(Theme_Address);
        if(index.column() == 7) return THEME_VALUE(Theme_Data);
    }
    else if(role == Qt::TextAlignmentRole)
    {
        if(index.column() == 0) return QVariant{Qt::AlignRight | Qt::AlignVCenter};
        if(index.column() == 7) return QVariant{Qt::AlignLeft | Qt::AlignVCenter};
        return Qt::AlignCenter;
    }

    return QVariant();
}

QVariant SegmentsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole) return QVariant();

    switch(section)
    {
        case 0: return tr("Name");
        case 1: return tr("Start Address");
        case 2: return tr("End Address");
        case 3: return tr("Size");
        case 4: return tr("Offset");
        case 5: return tr("End Offset");
        case 6: return tr("Raw Size");
        case 7: return tr("Flags");
        default: break;
    }

    return QVariant();
}

int SegmentsModel::columnCount(const QModelIndex &) const { return 8; }
int SegmentsModel::rowCount(const QModelIndex&) const { return m_document ? RDDocument_GetSegments(m_document, nullptr) : 0; }

QString SegmentsModel::segmentFlags(const RDSegment& segment)
{
    QString s;
    if(HAS_FLAG(&segment, SegmentFlags_Code)) ADD_SEGMENT_FLAG(s, "CODE")
    if(HAS_FLAG(&segment, SegmentFlags_Data)) ADD_SEGMENT_FLAG(s, "DATA")
    if(HAS_FLAG(&segment, SegmentFlags_Bss))  ADD_SEGMENT_FLAG(s, "BSS")
    return s;
}
