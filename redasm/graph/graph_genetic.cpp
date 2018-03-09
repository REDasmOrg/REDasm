#include "graph_genetic.h"

namespace REDasm {
namespace Graphing {

GraphGenetic::GraphGenetic(Graph *graph): genetic<LayeredGraph, VertexList>()
{

}

GraphGenetic::individual_t GraphGenetic::make_child() const
{

}

fitness_t GraphGenetic::fitness(genetic::individual_t &individual, genetic::individual_t &) const
{

}

size_t GraphGenetic::allele_size(const genetic::individual_t &individual) const
{

}

GraphGenetic::allele_t &GraphGenetic::get_allele(genetic::individual_t &individual, size_t index) const
{

}

void GraphGenetic::set_allele(genetic::individual_t &individual, size_t index, const genetic::allele_t &allele) const
{

}

void GraphGenetic::append_allele(genetic::individual_t &dest, genetic::individual_t &src, genetic::allele_t allele) const
{

}

void GraphGenetic::mutate(genetic::allele_t &allele) const
{

}

size_t GraphGenetic::get_child_count(const genetic::population_t &candidates) const
{

}

} // namespace Graphing
} // namespace REDasm
