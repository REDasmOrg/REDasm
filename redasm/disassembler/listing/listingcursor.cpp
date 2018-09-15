#include "listingcursor.h"

namespace REDasm {

ListingCursor::ListingCursor(): m_currentline(-1), m_currentcolumn(0) { }
int ListingCursor::currentLine() const { return m_currentline; }
int ListingCursor::currentColumn() const { return m_currentcolumn; }

void ListingCursor::select(int line, int column)
{
    if((m_currentline == line) && (m_currentcolumn == column))
        return;

    m_currentline = line;
    m_currentcolumn = column;
    selectionChanged();
}

} // namespace REDasm
