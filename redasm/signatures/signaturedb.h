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
        struct Graph;
        typedef std::shared_ptr<Graph> GraphPtr;
        typedef std::list<GraphPtr> EdgeList;

        struct Graph {
            std::string pattern;
            EdgeList edges;
            s32 index;

            Graph(): index(-1) { }
            bool isLeaf() const { return edges.empty(); }
        };

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
        bool match(const std::string& hexbytes, Signature &signature) const;
        bool write(const std::string& name, const std::string &file);
        bool read(const std::string& file);
        bool readPath(const std::string& signame);
        SignatureDB& operator<<(const SignatureList& signatures);
        SignatureDB& operator<<(Signature signature);
        const Signature& operator[](size_t index) const;

    private:
        std::string uncollide(const std::string &name);
        EdgeList::iterator findEdge(const GraphPtr& graph, const std::string& pattern) const;
        void eachHexByte(const std::string& hexstring, std::function<bool(const std::string&, u32)> cb) const;

    private:
        u32 _signaturetype, _longestpattern;              // Signature type, Longest pattern length
        std::string _name;
        std::set<std::string> _duplicates;                // Signatures
        std::unordered_map<std::string, u32> _collisions; // Names
        std::unordered_map<std::string, GraphPtr> _graph; // Matching Graph
        SignatureList _signatures;
};

} // namespace REDasm

#endif // SIGNATUREDB_H
