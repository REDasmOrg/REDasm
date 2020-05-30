#pragma once

#include <QDockWidget>
#include "../hooks/idisposable.h"
#include "listingmap.h"

class ListingMapDock : public QDockWidget, public IDisposable
{
    Q_OBJECT

    public:
        explicit ListingMapDock(IDisassemblerCommand* command, QWidget *parent = nullptr);
        ListingMap* listingMap() const;
        void dispose() override;

    private:
        ListingMap* m_listingmap;
};

