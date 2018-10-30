#ifndef PATPARSER_H
#define PATPARSER_H

#include "../redasm.h"

namespace REDasm {

class PatParser
{
    private:
        enum PatNameType { Public = 0, Local, Private, Unnamed };

        struct PatName
        {
            u32 type;
            s64 offset;
            std::string name;
        };

        struct PatItem
        {
            PatItem(): alen(0), asum(0), modlen(0) { }

            std::string name, pattern, tail;
            u16 alen;
            u32 asum, modlen;
            std::vector<PatName> names, refnames;
        };

    public:
        PatParser();
        bool load(const std::string& patfile);
        const SignatureList& signatures() const;

    private:
        bool parse(std::ifstream &fs);

    private:
        SignatureList m_signatures;
        std::set<std::string> m_duplicates;
};

} // namespace REDasm

#endif // PATPARSER_H
