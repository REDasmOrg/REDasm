#pragma once

#include "contextmodel.h"
#include <rdapi/rdapi.h>

class ReferencesModel : public ContextModel
{
    Q_OBJECT

    public:
        explicit ReferencesModel(QObject *parent = nullptr);
        void xref(rd_address address);

    public:
        QModelIndex index(int row, int column, const QModelIndex&) const override;
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int rowCount(const QModelIndex&) const override;
        int columnCount(const QModelIndex&) const override;

    public slots:
        void clear();

    private:
        QString referenceFlags(const RDReference& reference) const;
        QString direction(rd_address address) const;

    private:
        SurfaceQt* m_surface;
        const RDReference* m_references{nullptr};
        size_t m_referencescount{0};
};
