#include "listingmapdock.h"

ListingMapDock::ListingMapDock(const RDContextPtr& ctx, QWidget *parent): QDockWidget(parent)
{
    m_listingmap = new ListingMap(ctx, this);
    this->setWidget(m_listingmap);
}

ListingMap* ListingMapDock::listingMap() const { return m_listingmap; }
