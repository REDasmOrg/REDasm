#include "segmentsmodel.h"
#include <QFontDatabase>
#include <QColor>

#define SEGMENT_TYPE(s, t) { if(!s.isEmpty()) s += " | ";  s += t; }

SegmentsModel::SegmentsModel(QObject *parent) : DisassemblerModel(parent), m_format(NULL)
{

}

void SegmentsModel::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    this->beginResetModel();
    DisassemblerModel::setDisassembler(disassembler);
    this->m_format = disassembler->format();
    this->endResetModel();
}

QVariant SegmentsModel::data(const QModelIndex &index, int role) const
{
    if(!this->m_format)
        return QVariant();

    /*
    if(role == Qt::DisplayRole)
    {
        const REDasm::Segment& s = m_format->segments()[index.row()];

        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(s.address, this->m_format->bits()));
        else if(index.column() == 1)
            return S_TO_QS(REDasm::hex(s.endaddress, this->m_format->bits()));
        else if(index.column() == 2)
            return QString::fromStdString(s.name);
        else if(index.column() == 3)
            return this->segmentFlags(s);
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 2)
            return QColor(Qt::darkGreen);
        else if(index.column() == 3)
            return QColor(Qt::darkRed);

        return QColor(Qt::darkBlue);

    }
    else if(role == Qt::TextAlignmentRole)
        return Qt::AlignCenter;
    else if(role == Qt::FontRole && index.column() != 3)
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);
        */

    return QVariant();
}

QVariant SegmentsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return QVariant();

    if(section == 0)
        return "Start Address";

    if(section == 1)
        return "End Address";

    if(section == 2)
        return "Name";

    if(section == 3)
        return "Type";

    return QVariant();
}

int SegmentsModel::rowCount(const QModelIndex &) const
{
    if(!this->m_format)
        return 0;

    return 0; //this->m_format->segments().size();
}

int SegmentsModel::columnCount(const QModelIndex &) const
{
    return 4;
}

QString SegmentsModel::segmentFlags(const REDasm::Segment &block) const
{
    QString s;

    if(block.type & REDasm::SegmentTypes::Code)
        SEGMENT_TYPE(s, "CODE")

    if(block.type & REDasm::SegmentTypes::Data)
        SEGMENT_TYPE(s, "DATA")

    if(block.type & REDasm::SegmentTypes::Bss)
        SEGMENT_TYPE(s, "BSS")

    return s;

}
