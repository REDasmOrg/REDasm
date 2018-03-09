#ifndef GRAPH_GENETIC_H
#define GRAPH_GENETIC_H

#include "../support/genetic.h"
#include "graph.h"

namespace REDasm {
namespace Graphing {

class GraphGenetic : public genetic<LayeredGraphPtr, VertexList>
{
    private:

    public:
        GraphGenetic(Graph* graph);

    protected:
        virtual individual_t make_child() const;
        virtual fitness_t fitness(individual_t &individual, individual_t &) const;
        virtual size_t allele_size(const individual_t& individual) const;
        virtual allele_t& get_allele(individual_t& individual, size_t index) const;
        virtual void append_allele(individual_t& dest, individual_t& src, size_t index) const;
        virtual void mutate(allele_t& allele) const;
        virtual size_t get_child_count(const population_t& candidates) const;
        virtual void generation_completed(const individual_fitness_t & individualfitness) const;

    private:
        u64 crossingCount(const LayeredGraphPtr &lgraph) const;
        u64 crossingCount(const VertexList& layer1, const VertexList &layer2) const;
        static size_t indexOfEdge(vertex_id_t edge, const VertexList& vl);
        static bool linesCrossing(size_t a1, size_t a2, size_t b1, size_t b2);

    private:
        Graph* _graph;
};

} // namespace Graphing
} // namespace REDasm

#endif // GRAPH_GENETIC_H
