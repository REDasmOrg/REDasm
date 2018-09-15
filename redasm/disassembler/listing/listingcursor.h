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
        void select(int line);

    private:
        int m_currentline;
};

} // namespace REDasm

#endif // LISTINGCURSOR_H
