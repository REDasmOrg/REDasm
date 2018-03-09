#ifndef GRAPH_GENETIC_H
#define GRAPH_GENETIC_H

#include "../support/genetic.h"
#include "graph.h"

namespace REDasm {
namespace Graphing {

class GraphGenetic : public genetic<LayeredGraph, VertexList>
{
    public:
        GraphGenetic(Graph* graph);

    protected:
        virtual individual_t make_child() const;
        virtual fitness_t fitness(individual_t &individual, individual_t &) const;
        virtual size_t allele_size(const individual_t& individual) const;
        virtual allele_t& get_allele(individual_t& individual, size_t index) const;
        virtual void set_allele(individual_t& individual, size_t index, const allele_t& allele) const;
        virtual void append_allele(individual_t& dest, individual_t& src, allele_t allele) const;
        virtual void mutate(allele_t& allele) const;
        virtual size_t get_child_count(const population_t& candidates) const;
};

} // namespace Graphing
} // namespace REDasm

#endif // GRAPH_GENETIC_H
