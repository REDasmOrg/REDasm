#ifndef SEGMENTSMODEL_H
#define SEGMENTSMODEL_H

#include "disassemblermodel.h"

class SegmentsModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit SegmentsModel(QObject *parent = 0);
        virtual void setDisassembler(REDasm::Disassembler *disassembler);

    public:
        virtual QVariant data(const QModelIndex &index, int role) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual int rowCount(const QModelIndex&) const;
        virtual int columnCount(const QModelIndex&) const;

    private:
        QString segmentFlags(const REDasm::Segment& block) const;

    private:
        const REDasm::FormatPlugin* m_format;
};

#endif // SEGMENTSMODEL_H
