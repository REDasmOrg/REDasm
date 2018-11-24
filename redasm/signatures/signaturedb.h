#ifndef SIGNATUREDB_H
#define SIGNATUREDB_H

#include "../redasm.h"
#include <unordered_map>
#include <vector>
#include <set>

#define SIGNATURE_PATTERN_LENGTH 32

namespace REDasm {

class SignatureDB
{
    private:
        struct Graph {
            std::string pattern;
            s32 index;
            bool isleaf;

            Graph(): index(-1), isleaf(true) { }
            Graph(const std::string& pattern): pattern(pattern), index(-1), isleaf(true) { }
        };

        typedef std::unique_ptr<Graph> GraphPtr;
        typedef std::list<GraphPtr> EdgeList;
        typedef std::unordered_map<std::string, u32> CollisionMap;
        typedef std::unordered_map<std::string, GraphPtr> GraphMap;
        typedef std::unordered_map<Graph*, EdgeList> EdgeMap;

    public:
        enum: u32 { REDasmSignature, IDASignature };

    public:
        SignatureDB();
        u32 count() const;
        u32 longestPattern() const;
        u32 signatureType() const;
        SignatureList::iterator begin();
        SignatureList::iterator end();
        void setSignatureType(u32 signaturetype);
        bool match(const std::string& hexstring, Signature &signature);
        bool write(const std::string& name, const std::string &file);
        bool read(const std::string& file);
        bool readPath(const std::string& signame);
        SignatureDB& operator<<(const SignatureList& signatures);
        SignatureDB& operator<<(Signature signature);
        const Signature& operator[](size_t index) const;

    private:
        std::string uncollide(const std::string &name);
        EdgeList::iterator findEdge(EdgeList &edges, const std::string& pattern);
        void eachHexByte(const std::string& hexstring, std::function<bool(const std::string&, u32)> cb) const;

    private:
        u32 m_signaturetype, m_longestpattern; // Signature type, Longest pattern length
        std::string m_name;
        std::set<std::string> m_duplicates;   // Signatures
        CollisionMap m_collisions;            // Names
        GraphMap m_graph;                     // Matching Graph
        EdgeMap m_edges;                      // Edges
        SignatureList m_signatures;
};

} // namespace REDasm

#endif // SIGNATUREDB_H
