#include "patparser.h"
#include <fstream>
#include <iomanip>

namespace REDasm {

PatParser::PatParser() { }

bool PatParser::load(const std::string &patfile)
{
    std::ifstream fs(patfile);

    if(!fs.good())
        return false;

    while(!fs.eof())
    {
        if(!this->parse(fs))
        {
            m_signatures.clear();
            return false;
        }
    }

    fs.close();
    return true;
}

const SignatureList &PatParser::signatures() const { return m_signatures; }

bool PatParser::parse(std::ifstream &fs)
{
    PatItem pi;
    std::getline(fs, pi.pattern, ' ');

    if(pi.pattern.find("---") == 0)
        return true;

    char c = 0;

    fs >> std::noskipws >> std::hex >> pi.alen >> c;
    fs >> std::hex >> pi.asum >> c;
    fs >> std::hex >> pi.modlen >> c;

    while(fs.peek() == ':' || fs.peek() == '^')
    {
        bool isreference = false;
        PatName pn;
        std::string offset;

        fs >> offset >> c;
        fs >> pn.name >> c;

        if(offset.front() == '^')
            isreference = true;
        else if(offset.front() != ':')
            return false;

        if(offset.back() == '@')
        {
            pn.type = PatNameType::Local;
            pn.offset = std::stoul(offset.substr(1, -1), NULL, 16);
        }
        else
        {
            pn.type = (pn.name == "?") ? PatNameType::Unnamed : PatNameType::Public;
            pn.offset = std::stoul(offset.substr(1), NULL, 16);
        }

        if(!pn.offset && (pn.type != PatNameType::Unnamed))
            pi.name = pn.name;

        if(isreference)
            pi.refnames.push_back(pn);
        else
            pi.names.push_back(pn);
    }

    if((fs.peek() != '\r') && (fs.peek() != '\n'))
        fs >> pi.tail;

    while((fs.peek() == '\r') || (fs.peek() == '\n'))
        fs >> c;

    if(pi.name.empty()) // Skip unnamed signatures
        return true;

    Signature sig;
    sig.name = pi.name;
    sig.pattern = pi.pattern;
    sig.alen = pi.alen;
    sig.asum = pi.asum;

    m_signatures.push_back(sig);
    return true;
}

} // namespace REDasm
