#ifndef CHECKEDITEMSMODEL_H
#define CHECKEDITEMSMODEL_H

#include <QAbstractListModel>
#include <redasm/redasm_ui.h>

class CheckedItemsModel : public QAbstractListModel
{
    public:
        CheckedItemsModel(REDasm::UI::CheckList& items, QObject* parent = nullptr);
        void uncheckAll();

    public:
        Qt::ItemFlags flags(const QModelIndex &index) const;
        virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;
        virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
        virtual bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);

    private:
        REDasm::UI::CheckList& m_items;
};

#endif // CHECKEDITEMSMODEL_H
