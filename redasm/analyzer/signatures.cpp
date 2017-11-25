#include "signatures.h"
#include <fstream>

#define WILDCARD_CHARS "??"

namespace REDasm {

Signatures::Signatures()
{

}

bool Signatures::match(const std::string &data, const std::string &sig) const
{
    if(data.size() != sig.size())
        return false;

    size_t i = 0;

    while(i < data.size())
    {
        std::string s = sig.substr(i, 2);

        if(s != WILDCARD_CHARS)
        {
            std::string b = data.substr(i, 2);

            if(b != s)
                return false;
        }

        i += 2;
    }

    return true;
}

void Signatures::load(const std::string &signaturefile)
{
    std::fstream fs(signaturefile, std::ios::in);
    picojson::parse(this->_signatureobj, fs);
    fs.close();
}

const picojson::array &Signatures::signatures() const
{
    return this->_signatureobj.get("signatures").get<picojson::array>();
}

std::string Signatures::name() const
{
    return this->_signatureobj.get("name").to_str();
}

} // namespace REDasm
