#ifndef GRAPHLAYOUT_H
#define GRAPHLAYOUT_H

#include "graphbuilder.h"

namespace REDasm {

class GraphLayout
{
    private:
        typedef std::list<address_t> Columns;
        typedef std::list<Columns> Rows;

    public:
        GraphLayout();
        void layout(const GraphBuilder& gb);

    private:
        void initialize(const GraphBuilder& gb);
        void addRow();

    private:
        Rows _matrix;
};

} // namespace REDasm

#endif // GRAPHLAYOUT_H
