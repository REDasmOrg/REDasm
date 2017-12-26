#include "signaturedb.h"
#include "../support/serializer.h"
#include <fstream>

#define WILDCARD_BYTE      ".."
#define RDB_SIGNATURE_EXT  ".rdb"
#define RDB_SIGNATURE      "RDB"
#define RDB_SIGNATURE_SIZE 3

namespace REDasm {

SignatureDB::SignatureDB(): _signaturetype(SignatureDB::REDasmSignature), _longestpattern(0)
{

}

u32 SignatureDB::count() const
{
    return this->_signatures.size();
}

u32 SignatureDB::longestPattern() const
{
    return this->_longestpattern;
}

u32 SignatureDB::signatureType() const
{
    return this->_signaturetype;
}

SignatureList::iterator SignatureDB::begin()
{
    return this->_signatures.begin();
}

SignatureList::iterator SignatureDB::end()
{
    return this->_signatures.end();
}

void SignatureDB::setSignatureType(u32 signaturetype)
{
    this->_signaturetype = signaturetype;
}

bool SignatureDB::match(const std::string &hexbytes, Signature& signature)
{
    bool failed = false;
    Graph* currentgraph = NULL;

    this->eachHexByte(hexbytes, [this, &currentgraph, &failed](const std::string& pattern, u32 i) -> bool {
        if(i == 0) {
            auto it = this->_graph.find(pattern);

            if(it != this->_graph.end())
                currentgraph = it->second.get();
            else
                it = this->_graph.find(WILDCARD_BYTE);

            if(it != this->_graph.end())
                currentgraph = it->second.get();
            else
                return false;

            return true;
        }

        auto it = this->findEdge(currentgraph, pattern);

        if(it == currentgraph->edges.end()) {
            if(!currentgraph->isLeaf())
                failed = true;

            return false;
        }
        else
            currentgraph = (*it).get();

        return true;
    });

    if(!currentgraph)
        return false;

    if(!failed && currentgraph->isLeaf() && (currentgraph->index > -1))
    {
        signature = this->_signatures[currentgraph->index];
        return true;
    }

    return false;
}

bool SignatureDB::write(const std::string &name, const std::string& file)
{
    if(this->_signatures.empty())
        return false;

    std::fstream ofs(file, std::ios::out | std::ios::trunc | std::ios::binary);

    if(!ofs.is_open())
        return false;

    this->_name = name;

    ofs.write(RDB_SIGNATURE, 3);
    Serializer::serializeString(ofs, this->_name);
    Serializer::serializeScalar(ofs, this->_signatures.size(), sizeof(u32));
    Serializer::serializeScalar(ofs, this->_signaturetype);
    Serializer::serializeScalar(ofs, this->_longestpattern);

    std::for_each(this->_signatures.begin(), this->_signatures.end(), [&ofs](const Signature& sig) {
        Serializer::serializeString(ofs, sig.name);
        Serializer::obfuscateString(ofs, sig.pattern);
        Serializer::serializeScalar(ofs, sig.alen);
        Serializer::serializeScalar(ofs, sig.asum);
    });

    ofs.close();
    return true;
}

bool SignatureDB::read(const std::string &file)
{
    std::fstream ifs(file, std::ios::in | std::ios::binary);

    if(!ifs.is_open())
        return false;

    std::string sign;
    sign.resize(RDB_SIGNATURE_SIZE);
    ifs.read(&sign.front(), RDB_SIGNATURE_SIZE);

    if(sign != RDB_SIGNATURE)
        return false;

    u32 count = 0;
    Serializer::deserializeString(ifs, this->_name);
    Serializer::deserializeScalar(ifs, &count);
    Serializer::deserializeScalar(ifs, &this->_signaturetype);
    Serializer::deserializeScalar(ifs, &this->_longestpattern);

    for(u32 i = 0; i < count; i++)
    {
        Signature sig;

        Serializer::deserializeString(ifs, sig.name);
        Serializer::deobfuscateString(ifs, sig.pattern);
        Serializer::deserializeScalar(ifs, &sig.alen);
        Serializer::deserializeScalar(ifs, &sig.asum);

        *this << sig;
    }

    return true;
}

bool SignatureDB::readPath(const std::string &signame)
{
    return this->read(REDasm::makeDbPath("rdb", signame + RDB_SIGNATURE_EXT));
}

SignatureDB &SignatureDB::operator<<(const SignatureList &signatures)
{
    std::for_each(signatures.begin(), signatures.end(), [this](const Signature& signature) {
        *this << signature;
    });

    return *this;
}

SignatureDB &SignatureDB::operator<<(Signature signature)
{
    if(this->_duplicates.find(signature.pattern) != this->_duplicates.end())
        return *this;

    this->_longestpattern = std::max(this->_longestpattern, static_cast<u32>(signature.length()));

    signature.name = this->uncollide(signature.name);
    this->_duplicates.insert(signature.pattern);

    Graph* currentgraph = NULL;

    this->eachHexByte(signature.pattern, [this, &currentgraph](const std::string& pattern, u32 i) -> bool {
        if(i == 0) {
            auto it = this->_graph.find(pattern);

            if(it == this->_graph.end())
            {
                this->_graph[pattern] = std::make_unique<Graph>(pattern);
                currentgraph = this->_graph[pattern].get();
            }
            else
                currentgraph = it->second.get();
        }
        else {
            auto it = this->findEdge(currentgraph, pattern);

            if(it == currentgraph->edges.end())
            {
                currentgraph->edges.push_back(std::make_unique<Graph>(pattern));
                currentgraph = currentgraph->edges.back().get();

            }
            else
                currentgraph = (*it).get();
        }

        return true;
    });

    currentgraph->index = this->_signatures.size();
    this->_signatures.push_back(signature);
    return *this;
}

const Signature &SignatureDB::operator[](size_t index) const
{
    return this->_signatures[index];
}

std::string SignatureDB::uncollide(const std::string &name)
{
    auto it = this->_collisions.find(name);

    if(it != this->_collisions.end())
        return name + "_" + std::to_string(++(it->second));
    else
        this->_collisions[name] = 0;

    return name;
}

SignatureDB::EdgeList::iterator SignatureDB::findEdge(Graph* graph, const std::string &pattern)
{
    EdgeList::iterator wit = graph->edges.end();

    for(auto it = graph->edges.begin(); it != graph->edges.end(); it++)
    {
        if((*it)->pattern == pattern)
            return it;
        else if((*it)->pattern == WILDCARD_BYTE)
            wit = it;
    }

    if(wit != graph->edges.end())
        return wit;

    return graph->edges.end();
}

void SignatureDB::eachHexByte(const std::string &hexstring, std::function<bool(const std::string &, u32)> cb) const
{
    for(u32 i = 0; i < hexstring.size(); i += 2)
    {
        std::string pattern = hexstring.substr(i, 2);
        std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::toupper);

        if(!cb(pattern, i))
            break;
    }
}

} // namespace REDasm
