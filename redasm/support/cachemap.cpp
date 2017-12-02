#include "cachemap.h"

namespace REDasm {
namespace Serializer {

void serializeString(std::fstream& fs, const std::string& s)
{
    Serializer::serializeScalar(fs, s.size(), sizeof(u32));
    fs << s;
}

void deserializeString(std::fstream& fs, std::string& s)
{
    u32 size = 0;
    Serializer::deserializeScalar(fs, &size, sizeof(u32));

    s.resize(size);
    fs.read(&s[0], size);
}

} // namespace Serializer
} // namespace REDasm
