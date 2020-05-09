#pragma once

#include <QDockWidget>
#include "listingmap.h"

class ListingMapDock : public QDockWidget
{
    Q_OBJECT

    public:
        explicit ListingMapDock(IDisassemblerCommand* command, QWidget *parent = nullptr);
        ListingMap* listingMap() const;

    private:
        ListingMap* m_listingmap;
};

