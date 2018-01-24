#include "graphlayout.h"

namespace REDasm {

GraphLayout::GraphLayout()
{

}

void GraphLayout::layout(const GraphBuilder &gb)
{
    this->initialize(gb);
}

void GraphLayout::initialize(const GraphBuilder &gb)
{
    this->_matrix.clear();

    std::for_each(gb._nodes.begin(), gb._nodes.end(), [this](std::pair<address_t, const GraphNodePtr&> item) {
        Columns columns;
        columns.push_back(item.first);
        this->_matrix.push_back(columns);
    });
}

void GraphLayout::addRow()
{

}

} // namespace REDasm
