#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <string>
#include <picojson.h>

namespace REDasm {

class Signatures
{
    public:
        Signatures();
        bool match(const std::string& data, const std::string& sig) const;
        void load(const std::string& signaturefile);
        const picojson::array &signatures() const;
        std::string name() const;

    private:
        picojson::value _signatureobj;
};

} // namespace REDasm

#endif // SIGNATURES_H
