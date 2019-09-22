#include "segmentsmodel.h"
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/plugins/loader/loader.h>
#include <redasm/support/utils.h>
#include <QColor>
#include "../themeprovider.h"
#include "../convert.h"

#define ADD_SEGMENT_TYPE(s, t) { if(!s.isEmpty()) s += " | ";  s += t; }

SegmentsModel::SegmentsModel(QObject *parent) : ListingItemModel(REDasm::ListingItemType::SegmentItem, parent) { }

QVariant SegmentsModel::data(const QModelIndex &index, int role) const
{
    if(!m_disassembler)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        const REDasm::Assembler* assembler = m_disassembler->assembler();
        const REDasm::Segment* segment = m_disassembler->documentNew()->segments()->at(index.row());

        switch(index.column())
        {
            case 0: return Convert::to_qstring(REDasm::String::hex(segment->address, assembler->bits()));
            case 1: return Convert::to_qstring(REDasm::String::hex(segment->endaddress, assembler->bits()));
            case 2: return Convert::to_qstring(REDasm::String::hex(segment->size(), assembler->bits()));
            case 3: return Convert::to_qstring(REDasm::String::hex(segment->offset, assembler->bits()));
            case 4: return Convert::to_qstring(REDasm::String::hex(segment->endoffset, assembler->bits()));
            case 5: return Convert::to_qstring(REDasm::String::hex(segment->rawSize(), assembler->bits()));
            case 6: return Convert::to_qstring(segment->name);
            case 7: return SegmentsModel::segmentFlags(segment);
            case 8: return (segment->coveragebytes == REDasm::npos) ? "N/A" : (QString::number((static_cast<double>(segment->coveragebytes) /
                                                                                                static_cast<double>(segment->rawSize())) * 100, 'g', 3) + "%");
            default: break;
        }
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 6) return THEME_VALUE("segment_name_fg");
        else if(index.column() == 7) return THEME_VALUE("segment_flags_fg");
        return THEME_VALUE("address_list_fg");
    }
    else if(role == Qt::TextAlignmentRole)
    {
        if(index.column() > 5) return Qt::AlignCenter;
        else return Qt::AlignRight;
    }

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
        case 6: return "Name";
        case 7: return "Type";
        case 8: return "Coverage";
        default: break;
    }

    return ListingItemModel::headerData(section, orientation, role);
}

int SegmentsModel::columnCount(const QModelIndex &) const { return 9; }

QString SegmentsModel::segmentFlags(const REDasm::Segment *segment)
{
    QString s;

    if(segment->is(REDasm::SegmentType::Code))
        ADD_SEGMENT_TYPE(s, "CODE")

    if(segment->is(REDasm::SegmentType::Data))
        ADD_SEGMENT_TYPE(s, "DATA")

    if(segment->is(REDasm::SegmentType::Bss))
        ADD_SEGMENT_TYPE(s, "BSS")

    return s;
}
