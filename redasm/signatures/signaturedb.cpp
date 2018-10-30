#include "signaturedb.h"
#include "../support/serializer.h"
#include <fstream>

#define WILDCARD_BYTE      ".."
#define RDB_SIGNATURE_EXT  ".rdb"
#define RDB_SIGNATURE      "RDB"
#define RDB_SIGNATURE_SIZE 3

namespace REDasm {

SignatureDB::SignatureDB(): m_signaturetype(SignatureDB::REDasmSignature), m_longestpattern(0) { }
u32 SignatureDB::count() const { return m_signatures.size(); }
u32 SignatureDB::longestPattern() const { return m_longestpattern; }
u32 SignatureDB::signatureType() const { return m_signaturetype; }
SignatureList::iterator SignatureDB::begin() { return m_signatures.begin(); }
SignatureList::iterator SignatureDB::end() { return m_signatures.end(); }
void SignatureDB::setSignatureType(u32 signaturetype) { m_signaturetype = signaturetype; }

bool SignatureDB::match(const std::string &hexbytes, Signature& signature)
{
    bool failed = false;
    Graph* currentgraph = NULL;

    this->eachHexByte(hexbytes, [this, &currentgraph, &failed](const std::string& pattern, u32 i) -> bool {
        if(i == 0) {
            auto it = m_graph.find(pattern);

            if(it != m_graph.end())
                currentgraph = it->second.get();
            else
                it = m_graph.find(WILDCARD_BYTE);

            if(it != m_graph.end())
                currentgraph = it->second.get();
            else
                return false;

            return true;
        }

        EdgeList& edges = m_edges[currentgraph];
        auto it = this->findEdge(edges, pattern);

        if(it == edges.end()) {
            if(!currentgraph->isleaf)
                failed = true;

            return false;
        }
        else
            currentgraph = (*it).get();

        return true;
    });

    if(!currentgraph)
        return false;

    if(!failed && currentgraph->isleaf && (currentgraph->index > -1))
    {
        signature = m_signatures[currentgraph->index];
        return true;
    }

    return false;
}

bool SignatureDB::write(const std::string &name, const std::string& file)
{
    if(m_signatures.empty())
        return false;

    std::fstream ofs(file, std::ios::out | std::ios::trunc | std::ios::binary);

    if(!ofs.is_open())
        return false;

    m_name = name;

    ofs.write(RDB_SIGNATURE, 3);
    Serializer::serializeString(ofs, m_name);
    Serializer::serializeScalar(ofs, m_signatures.size(), sizeof(u32));
    Serializer::serializeScalar(ofs, m_signaturetype);
    Serializer::serializeScalar(ofs, m_longestpattern);

    std::for_each(m_signatures.begin(), m_signatures.end(), [&ofs](const Signature& sig) {
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
    Serializer::deserializeString(ifs, m_name);
    Serializer::deserializeScalar(ifs, &count);
    Serializer::deserializeScalar(ifs, &m_signaturetype);
    Serializer::deserializeScalar(ifs, &m_longestpattern);

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
    if(m_duplicates.find(signature.pattern) != m_duplicates.end())
        return *this;

    m_longestpattern = std::max(m_longestpattern, static_cast<u32>(signature.length()));

    signature.name = this->uncollide(signature.name);
    m_duplicates.insert(signature.pattern);

    Graph* currentgraph = NULL;

    this->eachHexByte(signature.pattern, [this, &currentgraph](const std::string& pattern, u32 i) -> bool {
        if(i == 0) {
            auto it = m_graph.find(pattern);

            if(it == m_graph.end())
            {
                m_graph[pattern] = std::make_unique<Graph>(pattern);
                currentgraph = m_graph[pattern].get();
                m_edges[currentgraph] = EdgeList(); // Initialize Edges for this Graph
            }
            else
                currentgraph = it->second.get();
        }
        else {
            EdgeList& edges = m_edges[currentgraph];
            auto it = this->findEdge(edges, pattern);

            if(it == edges.end())
            {
                edges.push_back(std::make_unique<Graph>(pattern));
                currentgraph->isleaf = false;
                currentgraph = edges.back().get();
                m_edges[currentgraph] = EdgeList(); // Initialize Edges for this Graph

            }
            else
                currentgraph = (*it).get();
        }

        return true;
    });

    currentgraph->index = m_signatures.size();
    m_signatures.push_back(signature);
    return *this;
}

const Signature &SignatureDB::operator[](size_t index) const
{
    return m_signatures[index];
}

std::string SignatureDB::uncollide(const std::string &name)
{
    auto it = m_collisions.find(name);

    if(it != m_collisions.end())
        return name + "_" + std::to_string(++(it->second));
    else
        m_collisions[name] = 0;

    return name;
}

SignatureDB::EdgeList::iterator SignatureDB::findEdge(EdgeList& edges, const std::string &pattern)
{
    EdgeList::iterator wit = edges.end();

    for(auto it = edges.begin(); it != edges.end(); it++)
    {
        if((*it)->pattern == pattern)
            return it;
        else if((*it)->pattern == WILDCARD_BYTE)
            wit = it;
    }

    if(wit != edges.end())
        return wit;

    return edges.end();
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
