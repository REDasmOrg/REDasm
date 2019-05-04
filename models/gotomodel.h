#ifndef GOTOMODEL_H
#define GOTOMODEL_H

#include "listingitemmodel.h"

class GotoModel : public ListingItemModel
{
    Q_OBJECT

    public:
        explicit GotoModel(QObject *parent = nullptr);
        ~GotoModel();

    public:
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int columnCount(const QModelIndex&) const override;

    private:
        QColor itemColor(const REDasm::ListingItem* item) const;
        QString itemName(const REDasm::ListingItem* item) const;
        QString itemType(const REDasm::ListingItem* item) const;

    protected:
        bool isItemAllowed(const REDasm::ListingItem* item) const override;
};

#endif // GOTOMODEL_H
