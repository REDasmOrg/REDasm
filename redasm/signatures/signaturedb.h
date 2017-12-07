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
        SignatureDB();
        u32 count() const;
        SignatureList::iterator begin();
        SignatureList::iterator end();
        bool match(const std::string& pattern, Signature &signature) const;
        bool write(const std::string& name, const std::string &file);
        bool read(const std::string& file);
        bool readPath(const std::string& signame);
        SignatureDB& operator<<(const SignatureList& signatures);
        SignatureDB& operator<<(Signature signature);
        const Signature& operator[](size_t index) const;
        static void setPath(const std::string& path);

    private:
        std::string uncollide(const std::string &name);
        EdgeList::iterator findEdge(const GraphPtr& graph, const std::string& pattern) const;
        void eachHexByte(const std::string& hexstring, std::function<bool(const std::string&, u32)> cb) const;

    private:
        static std::string _path;
        std::string _name;
        std::set<std::string> _duplicates;                // Signatures
        std::unordered_map<std::string, u32> _collisions; // Names
        std::unordered_map<std::string, GraphPtr> _graph; // Matching Graph
        SignatureList _signatures;
};

} // namespace REDasm

#endif // SIGNATUREDB_H
