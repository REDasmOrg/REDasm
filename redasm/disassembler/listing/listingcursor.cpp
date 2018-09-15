#include "listingcursor.h"

namespace REDasm {

ListingCursor::ListingCursor(): m_currentline(-1) { }
int ListingCursor::currentLine() const { return m_currentline; }

void ListingCursor::select(int line)
{
    if(m_currentline == line)
        return;

    m_currentline = line;
    selectionChanged();
}

} // namespace REDasm
