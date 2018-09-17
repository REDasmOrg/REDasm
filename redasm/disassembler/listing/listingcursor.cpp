#include "listingcursor.h"

namespace REDasm {

ListingCursor::ListingCursor() { m_position = std::make_pair(0, 0); }
const std::string &ListingCursor::wordUnderCursor() const { return m_wordundercursor;  }
void ListingCursor::setWordUnderCursor(const std::string &s) { m_wordundercursor = s; }
void ListingCursor::clearWordUnderCursor() { m_wordundercursor.clear(); }
const ListingCursor::Position &ListingCursor::currentPosition() const { return m_position; }
int ListingCursor::currentLine() const { return m_position.first; }
int ListingCursor::currentColumn() const { return m_position.second; }
bool ListingCursor::canGoBack() const { return !m_backstack.empty(); }
bool ListingCursor::canGoForward() const { return !m_forwardstack.empty(); }
void ListingCursor::select(int line, int column) { this->select(line, column, true); }

void ListingCursor::goBack()
{
    if(m_backstack.empty())
        return;

    Position pos = m_backstack.top();
    m_backstack.pop();

    m_forwardstack.push(m_position);
    this->select(pos.first, pos.second, false);
    forwardChanged();
}

void ListingCursor::goForward()
{
    if(m_forwardstack.empty())
        return;

    Position pos = m_forwardstack.top();
    m_forwardstack.pop();

    m_backstack.push(m_position);
    this->select(pos.first, pos.second, false);
    forwardChanged();
}

void ListingCursor::select(int line, int column, bool save)
{
    Position pos = std::make_pair(line, column);

    if(pos == m_position)
        return;

    if(save)
    {
        m_backstack.push(m_position);
        backChanged();
    }

    m_position = pos;
    selectionChanged();
}

} // namespace REDasm
