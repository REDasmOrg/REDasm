#include "ordinals.h"
#include <fstream>
#include <json.hpp>

namespace REDasm {

using json = nlohmann::json;

bool loadordinals(const std::string &ordinalfile, OrdinalsMap &ordinals)
{
    std::ifstream ifs(ordinalfile);

    if(!ifs.is_open())
        return false;

    json js;
    ifs >> js;

    for(auto it = js.begin(); it != js.end(); it++)
    {
        std::string ordinalstring = it.key(), name = it.value();

        if(ordinalstring.empty() || name.empty())
            continue;

        try
        {
            u64 ordinal = std::stoi(ordinalstring);
            ordinals[ordinal] = name;
        }
        catch(...)
        {
            continue;
        }
    }

    ifs.close();
    return true;
}

std::string ordinal(const OrdinalsMap &ordinals, u64 ordinal, const std::string &fallbackprefix)
{
    auto it = ordinals.find(ordinal);

    if(it == ordinals.end())
        return fallbackprefix + "Ordinal__" + REDasm::hex(ordinal, 16);

    return it->second;
}

} // namespace REDasm
