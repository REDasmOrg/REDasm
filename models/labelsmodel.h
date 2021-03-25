#pragma once

#include "addressmodel.h"

class LabelsModel : public AddressModel
{
    Q_OBJECT

    public:
        explicit LabelsModel(const RDContextPtr& ctx, rd_flag flag, QObject *parent = nullptr);
        rd_address address(const QModelIndex& index) const override;

    public:
        int rowCount(const QModelIndex& = QModelIndex()) const override;
        int columnCount(const QModelIndex& = QModelIndex()) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    private:
        static QString escapeString(const QString& s);

    private:
        rd_type m_flag;
};

