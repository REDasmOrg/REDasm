#include "segmentsmodel.h"
#include <QColor>
#include "../themeprovider.h"

#define ADD_SEGMENT_TYPE(s, t) { if(!s.isEmpty()) s += " | ";  s += t; }

SegmentsModel::SegmentsModel(QObject *parent) : ListingItemModel(DocumentItemType_Segment, parent) { }

QVariant SegmentsModel::data(const QModelIndex &index, int role) const
{
    if(!m_document) return QVariant();

    if(role == Qt::DisplayRole)
    {
        const RDDocumentItem& item = this->item(index);
        RDSegment segment;
        RDDocument_GetSegmentAddress(m_document, item.address, &segment);

        switch(index.column())
        {
            case 0: return QString::fromUtf8(RD_ToHexBits(segment.address, RDDisassembler_Bits(m_disassembler.get()), false));
            case 1: return QString::fromUtf8(RD_ToHexBits(segment.endaddress, RDDisassembler_Bits(m_disassembler.get()), false));
            case 2: return QString::fromUtf8(RD_ToHexBits(RDSegment_Size(&segment), RDDisassembler_Bits(m_disassembler.get()), false));
            case 3: return QString::fromUtf8(RD_ToHexBits(segment.offset, RDDisassembler_Bits(m_disassembler.get()), false));
            case 4: return QString::fromUtf8(RD_ToHexBits(segment.endoffset, RDDisassembler_Bits(m_disassembler.get()), false));
            case 5: return QString::fromUtf8(RD_ToHexBits(RDSegment_RawSize(&segment), RDDisassembler_Bits(m_disassembler.get()), false));
            case 6: return SegmentsModel::segmentFlags(segment);
            case 7: return QString::fromUtf8(segment.name);
            default: break;
        }
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 6) return THEME_VALUE(Theme_Data);
        if(index.column() == 7) return THEME_VALUE(Theme_Symbol);
        if(index.column() < 6) return THEME_VALUE(Theme_Address);
    }
    else if(role == Qt::TextAlignmentRole)
        return Qt::AlignCenter;

    return QVariant();
}

QVariant SegmentsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return ListingItemModel::headerData(section, orientation, role);

    switch(section)
    {
        case 0: return "Start Address";
        case 1: return "End Address";
        case 2: return "Size";
        case 3: return "Offset";
        case 4: return "End Offset";
        case 5: return "Raw Size";
        case 6: return "Flags";
        case 7: return "Name";
        default: break;
    }

    return ListingItemModel::headerData(section, orientation, role);
}

int SegmentsModel::columnCount(const QModelIndex &) const { return 8; }

QString SegmentsModel::segmentFlags(const RDSegment& segment)
{
    QString s;
    if(HAS_FLAG(&segment, SegmentFlags_Code)) ADD_SEGMENT_TYPE(s, "CODE")
    if(HAS_FLAG(&segment, SegmentFlags_Data)) ADD_SEGMENT_TYPE(s, "DATA")
    if(HAS_FLAG(&segment, SegmentFlags_Bss))  ADD_SEGMENT_TYPE(s, "BSS")
    return s;
}
