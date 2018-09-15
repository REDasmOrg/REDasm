#include "listingcursor.h"

namespace REDasm {

ListingCursor::ListingCursor(): m_selectedline(0)
{

}

void ListingCursor::select(int line)
{
    if(m_selectedline == line)
        return;

    m_selectedline = line;
    selectionChanged();
}

} // namespace REDasm
