#ifndef GRAPHLAYOUT_H
#define GRAPHLAYOUT_H

#include "graphbuilder.h"

namespace REDasm {

class GraphLayout
{
    private:
        typedef std::vector<address_t> Columns;
        typedef std::vector<Columns> Rows;

    public:
        GraphLayout();
        void layout(const GraphBuilder& gb);

    private:
        void addRow();

    private:
        Rows _matrix;
};

} // namespace REDasm

#endif // GRAPHLAYOUT_H
