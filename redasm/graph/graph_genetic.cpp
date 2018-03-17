#include "graph_genetic.h"
#include <iostream>

#define MAX_GRAPHS 100

namespace REDasm {
namespace Graphing {

GraphGenetic::GraphGenetic(Graph *graph): genetic<LayeredGraphPtr, VertexList>(), _graph(graph)
{
    for(size_t i = 0; i < MAX_GRAPHS; i++)
    {
        LayeredGraphPtr lgraph = std::make_shared<LayeredGraph>(graph);

        if(!i && !this->crossingCount(lgraph))
            break;

        lgraph->shuffle();
        this->add_individual(lgraph);
    }
}

GraphGenetic::individual_t GraphGenetic::make_child() const { return std::make_shared<LayeredGraph>(); }
fitness_t GraphGenetic::fitness(GraphGenetic::individual_t &individual, GraphGenetic::individual_t &) const { return this->expected_fitness() - this->crossingCount(individual); }
size_t GraphGenetic::allele_size(const GraphGenetic::individual_t &individual) const { return individual->size();  }
GraphGenetic::allele_t &GraphGenetic::get_allele(GraphGenetic::individual_t &individual, size_t index) const { return individual->at(index); }
void GraphGenetic::append_allele(GraphGenetic::individual_t &dest, GraphGenetic::individual_t &src, size_t index) const { dest->push_back(src->at(index)); }

void GraphGenetic::mutate(GraphGenetic::allele_t &allele) const
{
    if(allele.size() == 1)
        return;

    if(allele.size() == 2)
    {
        std::iter_swap(allele.begin(), allele.rbegin());
        return;
    }

    size_t idx1 = std::rand() % allele.size(), idx2 = std::rand() % allele.size();
    std::iter_swap(allele.begin() + idx1, allele.begin() + idx2);
}

void GraphGenetic::generation_best_completed(const genetic::individual_fitness_t &individualfitness) const
{
    std::string s = "Graph generation ";
    s += std::to_string(this->generation()) + " with ";
    s += std::to_string(this->crossingCount(individualfitness.first)) + " crossing(s) & fitness ";
    s += std::to_string(individualfitness.second) + "%";

    REDasm::log(s);
}

u64 GraphGenetic::crossingCount(const LayeredGraphPtr& lgraph) const
{
    u64 crossings = 0;

    for(vertex_layer_t layer = 0; layer < lgraph->lastLayer(); layer++)
        crossings += this->crossingCount(lgraph->at(layer), lgraph->at(layer + 1));

    return crossings;
}

u64 GraphGenetic::crossingCount(const VertexList &layer1, const VertexList& layer2) const
{
    u64 count = 0;

    for(size_t i = 0; i < (layer1.size() - 1); i++)
    {
        Vertex *v1 = layer1[i], *v2 = layer1[i + 1];

        for(vertex_id_t edge1 : v1->edges)
        {
            size_t j = GraphGenetic::indexOfEdge(edge1, layer2);

            for(vertex_id_t edge2 : v2->edges)
            {
                size_t k = GraphGenetic::indexOfEdge(edge2, layer2);

                if(!GraphGenetic::linesCrossing(i, j, i + 1, k))
                    continue;

                count++;
            }
        }
    }

    return count;
}

size_t GraphGenetic::indexOfEdge(vertex_id_t edge, const VertexList &vl)
{
    size_t idx = 0;

    for(size_t i = 0; i < vl.size(); i++)
    {
        if(edge != vl[i]->id)
            continue;

        idx = i;
        break;
    }

    return idx;
}

bool GraphGenetic::linesCrossing(size_t a1, size_t a2, size_t b1, size_t b2) { return (a1 < b1 && a2 > b2) || (a1 > b1 && a2 < b2); }

} // namespace Graphing
} // namespace REDasm
