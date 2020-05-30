#include "listingmapdock.h"

ListingMapDock::ListingMapDock(IDisassemblerCommand* command, QWidget *parent) : QDockWidget(parent)
{
    m_listingmap = new ListingMap(this);
    m_listingmap->linkTo(command);
    this->setWidget(m_listingmap);
}

ListingMap* ListingMapDock::listingMap() const { return m_listingmap; }
void ListingMapDock::dispose() { m_listingmap->dispose(); this->deleteLater(); }
