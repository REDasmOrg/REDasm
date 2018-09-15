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
        void select(int line);

    private:
        int m_selectedline;
};

} // namespace REDasm

#endif // LISTINGCURSOR_H
