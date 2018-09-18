#include "listingcursor.h"

namespace REDasm {

ListingCursor::ListingCursor() { m_position = std::make_pair(0, 0); }
const std::string &ListingCursor::wordUnderCursor() const { return m_wordundercursor;  }
void ListingCursor::setWordUnderCursor(const std::string &s) { m_wordundercursor = s; }
void ListingCursor::clearWordUnderCursor() { m_wordundercursor.clear(); }
const ListingCursor::Position &ListingCursor::currentPosition() const { return m_position; }
const ListingCursor::Position &ListingCursor::currentSelection() const { return m_selection; }

const ListingCursor::Position &ListingCursor::startSelection() const
{
    if(m_position.first < m_selection.first)
        return m_position;

    if(m_position.first == m_selection.first)
    {
        if(m_position.second < m_selection.second)
            return m_position;
    }

    return m_selection;
}

const ListingCursor::Position &ListingCursor::endSelection() const
{
    if(m_position.first > m_selection.first)
        return m_position;

    if(m_position.first == m_selection.first)
    {
        if(m_position.second > m_selection.second)
            return m_position;
    }

    return m_selection;
}

int ListingCursor::currentLine() const { return m_position.first; }
int ListingCursor::currentColumn() const { return m_position.second; }
int ListingCursor::selectionLine() const { return m_selection.first; }
int ListingCursor::selectionColumn() const { return m_selection.second; }

bool ListingCursor::isLineSelected(int line) const
{
    if(!this->hasSelection())
        return false;

    int first = std::min(m_position.first, m_selection.first);
    int last = std::max(m_position.first, m_selection.first);

    if((line < first) || (line > last))
        return false;

    return true;
}

bool ListingCursor::hasSelection() const { return m_position != m_selection; }
bool ListingCursor::canGoBack() const { return !m_backstack.empty(); }
bool ListingCursor::canGoForward() const { return !m_forwardstack.empty(); }
void ListingCursor::moveTo(int line, int column) { this->moveTo(line, column, true); }

void ListingCursor::select(int line, int column)
{
    Position pos = std::make_pair(std::max(line, 0), std::max(column, 0));

    if(pos == m_position)
        return;

    m_position = pos;
    positionChanged();
}

void ListingCursor::goBack()
{
    if(m_backstack.empty())
        return;

    Position pos = m_backstack.top();
    m_backstack.pop();

    m_forwardstack.push(m_position);
    this->moveTo(pos.first, pos.second, false);
    forwardChanged();
}

void ListingCursor::goForward()
{
    if(m_forwardstack.empty())
        return;

    Position pos = m_forwardstack.top();
    m_forwardstack.pop();

    m_backstack.push(m_position);
    this->moveTo(pos.first, pos.second, false);
    forwardChanged();
}

void ListingCursor::moveTo(int line, int column, bool save)
{
    Position pos = std::make_pair(std::max(line, 0), std::max(column, 0));

    if(pos == m_position)
        return;

    if(save && !this->hasSelection())
    {
        m_backstack.push(m_position);
        backChanged();
    }

    m_selection = pos;
    this->select(line, column);
}

} // namespace REDasm
