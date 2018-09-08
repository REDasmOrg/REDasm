#ifndef SEGMENTSMODEL_H
#define SEGMENTSMODEL_H

#include "listingdocumentmodel.h"

class SegmentsModel : public ListingDocumentModel
{
    Q_OBJECT

    public:
        explicit SegmentsModel(QObject *parent = 0);

    public:
        virtual QModelIndex index(int row, int column, const QModelIndex &) const;
        virtual QVariant data(const QModelIndex &index, int role) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual int columnCount(const QModelIndex&) const;
        virtual int rowCount(const QModelIndex&) const;

    private:
        static QString segmentFlags(const REDasm::Segment* segment);
};

#endif // SEGMENTSMODEL_H
