#pragma once

#include "labelsmodel.h"

class StringsModel : public LabelsModel
{
    Q_OBJECT

    public:
        explicit StringsModel(const RDContextPtr& ctx, QObject* parent = 0);

    public:
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int columnCount(const QModelIndex&) const override;

    private:
        QString segment(const QModelIndex& index) const;
        QString string(const QModelIndex& index) const;
        static QString escapeString(const QString& s);
};

