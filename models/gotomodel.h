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
        virtual QVariant data(const QModelIndex &index, int role) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual int columnCount(const QModelIndex&) const;

    private:
        QColor itemColor(const REDasm::ListingItem* item) const;
        QString itemName(const REDasm::ListingItem* item) const;
        QString itemType(const REDasm::ListingItem* item) const;

    protected:
        virtual bool isItemAllowed(const REDasm::ListingItem* item) const;
};

#endif // GOTOMODEL_H
