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
        SimpleEvent positionChanged;
        SimpleEvent backChanged;
        SimpleEvent forwardChanged;

    public:
        ListingCursor();
        bool hasWordUnderCursor() const;
        void clearWordUnderCursor();
        void setWordUnderCursor(const std::string& s);
        const std::string& wordUnderCursor() const;
        const ListingCursor::Position& currentPosition() const;
        const ListingCursor::Position& currentSelection() const;
        const ListingCursor::Position& startSelection() const;
        const ListingCursor::Position& endSelection() const;
        int currentLine() const;
        int currentColumn() const;
        int selectionLine() const;
        int selectionColumn() const;
        bool isLineSelected(int line) const;
        bool hasSelection() const;
        bool canGoBack() const;
        bool canGoForward() const;
        void set(int line, int column = 0);
        void moveTo(int line, int column = 0);
        void select(int line, int column = 0);
        void goBack();
        void goForward();

    private:
        void moveTo(int line, int column, bool save);

    private:
        Position m_position, m_selection;
        PositionStack m_backstack, m_forwardstack;
        std::string m_wordundercursor;
};

} // namespace REDasm

#endif // LISTINGCURSOR_H
