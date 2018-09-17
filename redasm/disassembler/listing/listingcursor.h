#ifndef LISTINGCURSOR_H
#define LISTINGCURSOR_H

#include <stack>
#include "../../redasm.h"
#include "../../support/event.h"

namespace REDasm {

class ListingCursor
{
    public:
        typedef std::pair<int, int> Position;
        typedef std::stack<Position> PositionStack;

    public:
        SimpleEvent selectionChanged;
        SimpleEvent backChanged;
        SimpleEvent forwardChanged;

    public:
        ListingCursor();
        const std::string& wordUnderCursor() const;
        void setWordUnderCursor(const std::string& s);
        void clearWordUnderCursor();
        const ListingCursor::Position& currentPosition() const;
        int currentLine() const;
        int currentColumn() const;
        bool canGoBack() const;
        bool canGoForward() const;
        void select(int line, int column = 0);
        void goBack();
        void goForward();

    private:
        void select(int line, int column, bool save);

    private:
        Position m_position;
        PositionStack m_backstack, m_forwardstack;
        std::string m_wordundercursor;
};

} // namespace REDasm

#endif // LISTINGCURSOR_H
