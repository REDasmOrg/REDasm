#pragma once

#include <QAbstractListModel>
//#include <redasm/ui.h>

// class CheckedItemsModel : public QAbstractListModel
// {
//     Q_OBJECT
//
//     public:
//         CheckedItemsModel(REDasm::UI::CheckList& items, QObject* parent = nullptr);
//         void uncheckAll();
//
//     public:
//         Qt::ItemFlags flags(const QModelIndex &index) const override;
//         int rowCount(const QModelIndex &parent = QModelIndex()) const override;
//         QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
//         bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;
//
//     private:
//         REDasm::UI::CheckList& m_items;
// };
