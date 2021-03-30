#pragma once

#include <QAbstractListModel>
#include <rdapi/rdapi.h>
#include "../hooks/isurface.h"

class BlockListModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit BlockListModel(const RDContextPtr& ctx, rd_address address, QObject *parent = nullptr);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        QVariant data(const QModelIndex &index, int role) const override;
        int columnCount(const QModelIndex&) const override;
        int rowCount(const QModelIndex&) const override;

    private:
        QString blockType(const RDBlock* block) const;
        QString labelName(const RDBlock* block) const;

    private:
        QList<RDBlock> m_blocks;
        RDContextPtr m_context;
        RDDocument* m_document;
};

