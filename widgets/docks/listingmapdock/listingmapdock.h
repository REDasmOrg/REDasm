#pragma once

#include <QDockWidget>
#include "listingmap.h"

class ListingMapDock : public QDockWidget
{
    Q_OBJECT

    public:
        explicit ListingMapDock(const RDContextPtr& ctx, QWidget *parent = nullptr);
        ListingMap* listingMap() const;

    private:
        ListingMap* m_listingmap;
};

