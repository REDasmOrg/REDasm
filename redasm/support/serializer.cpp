#include "serializer.h"

namespace REDasm {
namespace Serializer {

std::string& xorify(std::string& s)
{
    u32 len = s.size();

    for(u32 i = 0; i < len; i++)
        s[i] ^= ((len - i) % 0x100u);

    return s;
}

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

void obfuscateString(std::fstream &fs, std::string s)
{
    xorify(s);
    Serializer::serializeString(fs, s);
}

void deobfuscateString(std::fstream &fs, std::string &s)
{
    Serializer::deserializeString(fs, s);
    xorify(s);
}

} // namespace Serializer
} // namespace REDasm
