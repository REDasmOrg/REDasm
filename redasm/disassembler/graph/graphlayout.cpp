#include "graphlayout.h"

namespace REDasm {

GraphLayout::GraphLayout()
{

}

void GraphLayout::layout(const GraphBuilder &gb)
{
    this->_matrix.clear();
    this->addRow();

    const GraphNodePtr& root = gb.rootNode();
    this->_matrix[0].push_back(root->start);
}

void GraphLayout::addRow()
{
    this->_matrix.push_back(Columns());
}

} // namespace REDasm
