#ifndef LISTITEMSMODEL_H
#define LISTITEMSMODEL_H

#include <QAbstractListModel>
#include <redasm/ui.h>

class ListItemsModel: public QAbstractListModel
{
    Q_OBJECT

    public:
        ListItemsModel(const REDasm::List& list, QObject* parent = nullptr);
        int rowCount(const QModelIndex &parent = QModelIndex()) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    private:
        const REDasm::List& m_items;
};

#endif // LISTITEMSMODEL_H
