#include "listingcursor.h"

namespace REDasm {

ListingCursor::ListingCursor() { m_position = std::make_pair(0, 0); }
int ListingCursor::currentLine() const { return m_position.first; }
int ListingCursor::currentColumn() const { return m_position.second; }
bool ListingCursor::hasBack() const { return !m_backstack.empty(); }
bool ListingCursor::hasForward() const { return !m_forwardstack.empty(); }

void ListingCursor::select(int line, int column)
{
    Position pos = std::make_pair(line, column);

    if(pos == m_position)
        return;

    m_backstack.push(m_position);
    m_position = pos;

    selectionChanged();
    backChanged();
}

void ListingCursor::back()
{
    if(m_backstack.empty())
        return;

    Position pos = m_backstack.top();
    m_backstack.pop();

    m_forwardstack.push(m_position);
    this->select(pos.first, pos.second);
    forwardChanged();
}

void ListingCursor::forward()
{
    if(m_forwardstack.empty())
        return;

    Position pos = m_forwardstack.top();
    m_forwardstack.pop();

    m_backstack.push(m_position);
    this->select(pos.first, pos.second);
    forwardChanged();
}

} // namespace REDasm
