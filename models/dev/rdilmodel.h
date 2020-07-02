#pragma once

#include <QAbstractListModel>
#include <rdapi/rdapi.h>
#include "../../hooks/idisassemblercommand.h"

class RDILModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit RDILModel(IDisassemblerCommand* command, QObject *parent = nullptr);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        QVariant data(const QModelIndex &index, int role) const override;
        int columnCount(const QModelIndex&) const override;
        int rowCount(const QModelIndex&) const override;

    private:
        std::vector<std::pair<RDILDisassembled, QString>> m_items;
        rd_ptr<RDRenderer> m_renderer;
};

