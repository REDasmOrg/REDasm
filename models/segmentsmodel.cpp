#include "segmentsmodel.h"
#include "../../redasm/plugins/format.h"
#include <QColor>

#define ADD_SEGMENT_TYPE(s, t) { if(!s.isEmpty()) s += " | ";  s += t; }

SegmentsModel::SegmentsModel(QObject *parent) : ListingItemModel(REDasm::ListingItem::SegmentItem, parent)
{

}

QVariant SegmentsModel::data(const QModelIndex &index, int role) const
{
    if(!m_disassembler)
        return DisassemblerModel::data(index, role);

    if(role == Qt::DisplayRole)
    {
        const REDasm::FormatPlugin* format = m_disassembler->format();
        const REDasm::Segment* segment = m_disassembler->document()->segmentAt(index.row());

        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(segment->address, format->bits()));
        else if(index.column() == 1)
            return S_TO_QS(REDasm::hex(segment->endaddress, format->bits()));
        else if(index.column() == 2)
            return S_TO_QS(segment->name);
        else if(index.column() == 3)
            return SegmentsModel::segmentFlags(segment);
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 2)
            return QColor(Qt::darkGreen);
        else if(index.column() == 3)
            return QColor(Qt::darkRed);

        return QColor(Qt::darkBlue);
    }

    return DisassemblerModel::data(index, role);
}

QVariant SegmentsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return ListingItemModel::headerData(section, orientation, role);

    if(section == 0)
        return "Start Address";

    if(section == 1)
        return "End Address";

    if(section == 2)
        return "Name";

    if(section == 3)
        return "Type";

    return ListingItemModel::headerData(section, orientation, role);
}

int SegmentsModel::columnCount(const QModelIndex &) const { return 4; }

QString SegmentsModel::segmentFlags(const REDasm::Segment *segment)
{
    QString s;

    if(segment->is(REDasm::SegmentTypes::Code))
        ADD_SEGMENT_TYPE(s, "CODE")

    if(segment->is(REDasm::SegmentTypes::Data))
        ADD_SEGMENT_TYPE(s, "DATA")

    if(segment->is(REDasm::SegmentTypes::Bss))
        ADD_SEGMENT_TYPE(s, "BSS")

    return s;
}
