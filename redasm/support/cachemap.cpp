#include "cachemap.h"

namespace REDasm {
namespace Serializer {

void serialize(std::fstream& fs, const std::string& s)
{
    u32 size = s.size();
    fs.write(reinterpret_cast<const char*>(&size), sizeof(u32));
    fs << s;
}

void deserialize(std::fstream& fs, std::string& s)
{
    u32 size = 0;
    fs.read(reinterpret_cast<char*>(&size), sizeof(u32));

    s.resize(size);
    fs.read(&s[0], size);
}

} // namespace Serializer
} // namespace REDasm
