#ifndef LISTINGCURSOR_H
#define LISTINGCURSOR_H

#include "../../redasm.h"
#include "../../support/event.h"

namespace REDasm {

class ListingCursor
{
    public:
        SimpleEvent selectionChanged;

    public:
        ListingCursor();
        int currentLine() const;
        int currentColumn() const;
        void select(int line, int column = 0);

    private:
        int m_currentline, m_currentcolumn;
};

} // namespace REDasm

#endif // LISTINGCURSOR_H
