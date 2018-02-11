#ifndef GRAPHBUILDER_H
#define GRAPHBUILDER_H

#include <functional>
#include "../types/listing.h"
#include "graphnode.h"

namespace REDasm {

class GraphBuilder
{
    friend class GraphLayout;

    private:
        typedef std::map<address_t, GraphNodePtr> Nodes;

    public:
        GraphBuilder(Listing& listing);
        u32 height() const;
        const GraphNodePtr& rootNode() const;
        const GraphNodePtr& getNode(address_t address);
        void build(address_t address);

    private:
        static u32 height(const GraphNodePtr& node) const;
        void buildNodesPass1();
        void buildNodesPass2();
        void buildNodesPass3();
        void buildNodesPass4();

    private:
        address_t _startaddress, _endaddress;
        Listing& _listing;
        Nodes _nodes;
};

} // namespace REDasm

#endif // GRAPHBUILDER_H
