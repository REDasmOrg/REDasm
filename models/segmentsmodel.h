#pragma once

#include "listingitemmodel.h"

class SegmentsModel : public ListingItemModel
{
    Q_OBJECT

    public:
        explicit SegmentsModel(QObject *parent = nullptr);

    public:
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int columnCount(const QModelIndex&) const override;

    private:
        static QString segmentFlags(const RDSegment& segment);
};
