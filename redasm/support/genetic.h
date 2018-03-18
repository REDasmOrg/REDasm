#ifndef GENETIC_H
#define GENETIC_H

#define GENETIC_MAX_GENERATION 100 // Stop at 100th generation
#define GENETIC_MUTATION_RATE   10 // Set mutation rate to 10%
#define GENETIC_BEST_RATE       30 // Set best rate to 30%
#define GENETIC_LUCKY_RATE      10 // Set lucky rate to 10%

#include <vector>
#include <utility>
#include <random>
#include <ctime>
#include <algorithm>
#include <cassert>

namespace REDasm {

typedef double fitness_t;
typedef size_t generation_t;

template<typename INDIVIDUAL, typename ALLELE> class genetic
{
    public:
        typedef INDIVIDUAL individual_t;
        typedef ALLELE allele_t;
        typedef std::pair<individual_t, fitness_t> individual_fitness_t;

    protected:
        typedef std::vector<individual_fitness_t> population_fitness_t;
        typedef std::vector<individual_t> population_t;

    public:
        genetic();
        bool empty() const { return _population.empty(); }
        size_t size() const { return _population.size(); }
        generation_t generation() const { return _generation; }
        void set_max_generation(size_t maxgen) { _maxgeneration = maxgen; }
        void set_mutation_rate(size_t rate) { _mutationrate = rate; }
        void set_best_rate(size_t rate) { _bestrate = rate; }
        void set_lucky_rate(size_t rate) { _luckyrate = rate; }
        void exterminate() { _population.clear(); }
        individual_fitness_t grow(individual_t expected);

    protected:
        void add_individual(const individual_t& individual) { _population.push_back(individual); }
        virtual void mutate_individual(individual_t& individual) const { this->mutate(this->get_allele(individual, std::rand() % this->allele_size(individual))); }
        virtual void generation_completed(const individual_fitness_t&) const { }
        virtual void generation_best_completed(const individual_fitness_t&) const { }
        virtual bool child_randomized() const { return (std::rand() % 100) < 50; }
        virtual individual_t create_child(individual_t& individual1, individual_t& individual2);
        virtual individual_t make_child() const { return individual_t(); }
        virtual fitness_t expected_fitness() const { return 100; }
        virtual fitness_t fitness(individual_t &individual, individual_t &expected) const;
        virtual size_t allele_size(const individual_t& individual) const = 0;
        virtual allele_t& get_allele(individual_t& individual, size_t index) const = 0;
        virtual void append_allele(individual_t& dest, individual_t& src, size_t index) const = 0;
        virtual void mutate(allele_t&) const { }

    private:
        void compute_fitness(population_fitness_t& populationfitness, individual_t &expected);
        void select_candidates(const population_fitness_t& populationfitness, population_t& candidates);
        void mutate_population();
        void create_children(population_t& candidates);
        size_t get_child_count(const population_t &candidates ) const;

    protected:
        population_t _population;

    private:
        size_t _generation, _maxpopulation, _maxgeneration;
        double _mutationrate, _bestrate, _luckyrate;

    private:
        static unsigned int _seed;
};

template<typename INDIVIDUAL, typename ALLELE> unsigned int genetic<INDIVIDUAL, ALLELE>::_seed = 0;

template<typename INDIVIDUAL, typename ALLELE> genetic<INDIVIDUAL, ALLELE>::genetic()
{
    this->_generation = this->_maxpopulation = 0;
    this->_maxgeneration = GENETIC_MAX_GENERATION;
    this->_mutationrate = GENETIC_MUTATION_RATE;
    this->_bestrate = GENETIC_BEST_RATE;
    this->_luckyrate = GENETIC_LUCKY_RATE;

    if(_seed)
        return;

    _seed = std::time(NULL);
    std::srand(_seed);
}

template<typename INDIVIDUAL, typename ALLELE> typename genetic<INDIVIDUAL, ALLELE>::individual_fitness_t genetic<INDIVIDUAL, ALLELE>::grow(individual_t expected)
{
    individual_fitness_t bestfitness;
    fitness_t maxfitness = 0;

    this->_generation = 1;
    this->_maxpopulation = this->_population.size();

    while(!this->_population.empty())
    {
        population_fitness_t populationfitness;
        this->compute_fitness(populationfitness, expected);

        population_t candidates;
        this->select_candidates(populationfitness, candidates);

        individual_fitness_t currbestfitness = populationfitness.front();

        if(currbestfitness.second > maxfitness)
        {
            bestfitness = currbestfitness;
            maxfitness = currbestfitness.second;
            this->generation_best_completed(bestfitness);
        }
        else
            this->generation_completed(currbestfitness);

        if((this->_generation >= this->_maxgeneration) || (currbestfitness.second == this->expected_fitness()))
            break;

        this->create_children(candidates);
        this->mutate_population();
        this->_generation++;
    }

    return bestfitness;
}

template<typename INDIVIDUAL, typename ALLELE> fitness_t genetic<INDIVIDUAL, ALLELE>::fitness(genetic::individual_t &individual, genetic::individual_t &expected) const
{
    size_t s = this->allele_size(individual);

    if(s != this->allele_size(expected))
        return 0;

    fitness_t score = 0;

    for(size_t i = 0; i < s; i++)
    {
        if(this->get_allele(individual, i) != this->get_allele(expected, i))
            continue;

        score++;
    }

    return score * 100 / s;
}

template<typename INDIVIDUAL, typename ALLELE> void genetic<INDIVIDUAL, ALLELE>::compute_fitness(genetic::population_fitness_t &populationfitness, individual_t &expected)
{
    populationfitness.reserve(this->_population.size());

    for(individual_t& individual : this->_population)
        populationfitness.push_back(std::make_pair(individual, this->fitness(individual, expected)));

    std::sort(populationfitness.begin(), populationfitness.end(), [](const individual_fitness_t& fitness1, const individual_fitness_t& fitness2) {
        return fitness1.second > fitness2.second;
    });
}

template<typename INDIVIDUAL, typename ALLELE> void genetic<INDIVIDUAL, ALLELE>::select_candidates(const genetic::population_fitness_t &populationfitness, genetic::population_t &candidates)
{
    ssize_t bestcount = populationfitness.size() * (this->_bestrate / 100.0);
    ssize_t luckycount = (populationfitness.size() - bestcount) * (this->_luckyrate / 100.0);

    for(ssize_t i = 0; i < bestcount; i++)
        candidates.push_back(populationfitness[i].first);

    for(ssize_t i = 0; i < luckycount; i++)
    {
        ssize_t idx = bestcount + (std::rand() % luckycount);

        if(std::find(candidates.rbegin(), candidates.rend(), populationfitness[idx].first) != candidates.rend())
            continue;

        candidates.push_back(populationfitness[idx].first);
    }

    std::random_shuffle(candidates.begin(), candidates.end());
}

template<typename INDIVIDUAL, typename ALLELE> void genetic<INDIVIDUAL, ALLELE>::mutate_population()
{
    for(individual_t& individual : this->_population)
    {
        if(static_cast<size_t>(std::rand() % 100) < this->_mutationrate)
            this->mutate_individual(individual);
    }
}

template<typename INDIVIDUAL, typename ALLELE> void genetic<INDIVIDUAL, ALLELE>::create_children(genetic::population_t &candidates)
{
    size_t childcount = this->get_child_count(candidates);

    if(!childcount)
        childcount = 1;

    this->_population.clear();

    for(size_t i = 0; i < (candidates.size() / 2); i++)
    {
        for(size_t j = 0; j < childcount; j++)
        {
            size_t idx1 = i, idx2 = candidates.size() - 1 - i;
            assert(idx1 != idx2);
            assert(this->allele_size(candidates[idx1]) == this->allele_size(candidates[idx2]));
            this->_population.push_back(this->create_child(candidates[idx1], candidates[idx2]));
        }
    }
}

template<typename INDIVIDUAL, typename ALLELE> size_t genetic<INDIVIDUAL, ALLELE>::get_child_count(const population_t& candidates) const
{
    return this->_maxpopulation / (candidates.size() / 2);
}

template<typename INDIVIDUAL, typename ALLELE> typename genetic<INDIVIDUAL, ALLELE>::individual_t genetic<INDIVIDUAL, ALLELE>::create_child(individual_t &individual1, individual_t &individual2)
{
    individual_t child = this->make_child();

    for(size_t i = 0; i < std::min(this->allele_size(individual1), this->allele_size(individual2)); i++)
    {
        if(this->child_randomized())
            this->append_allele(child, individual1, i);
        else
            this->append_allele(child, individual2, i);
    }

    return child;
}

} // namespace REDasm

#endif // GENETIC_H

