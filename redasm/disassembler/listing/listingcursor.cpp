#include "listingcursor.h"

namespace REDasm {

ListingCursor::ListingCursor() { m_position = std::make_pair(0, 0); }
bool ListingCursor::hasWordUnderCursor() const { return !m_wordundercursor.empty(); }
void ListingCursor::clearWordUnderCursor() { m_wordundercursor.clear(); }
void ListingCursor::setWordUnderCursor(const std::string &s) { m_wordundercursor = s; }
const std::string &ListingCursor::wordUnderCursor() const { return m_wordundercursor;  }
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

u64 ListingCursor::currentLine() const { return m_position.first; }
u64 ListingCursor::currentColumn() const { return m_position.second; }
u64 ListingCursor::selectionLine() const { return m_selection.first; }
u64 ListingCursor::selectionColumn() const { return m_selection.second; }

bool ListingCursor::isLineSelected(u64 line) const
{
    if(!this->hasSelection())
        return false;

    u64 first = std::min(m_position.first, m_selection.first);
    u64 last = std::max(m_position.first, m_selection.first);

    if((line < first) || (line > last))
        return false;

    return true;
}

bool ListingCursor::hasSelection() const { return m_position != m_selection; }
bool ListingCursor::canGoBack() const { return !m_backstack.empty(); }
bool ListingCursor::canGoForward() const { return !m_forwardstack.empty(); }
void ListingCursor::set(u64 line, u64 column) { this->moveTo(line, column, false); }
void ListingCursor::moveTo(u64 line, u64 column) { this->moveTo(line, column, true); }

void ListingCursor::select(u64 line, u64 column)
{
    m_position = std::make_pair(std::max(line, static_cast<u64>(0)),
                                std::max(column, static_cast<u64>(0)));

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

void ListingCursor::moveTo(u64 line, u64 column, bool save)
{
    Position pos = std::make_pair(std::max(line, static_cast<u64>(0)),
                                  std::max(column, static_cast<u64>(0)));

    if(save && !this->hasSelection())
    {
        m_backstack.push(m_position);
        backChanged();
    }

    m_selection = pos;
    this->select(line, column);
}

} // namespace REDasm
