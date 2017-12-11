#include "pe_ordinals.h"
#include <fstream>
#include <json.hpp>
#include <iostream>

namespace REDasm {

using json = nlohmann::json;

PEOrdinals::PEOrdinals()
{

}

void PEOrdinals::compile(const std::string &jsonfile, OrdinalMap &m)
{
    std::ifstream ifs(REDasm::makeFormatPath("pe", jsonfile + ".json"));

    if(!ifs.is_open())
        return;

    json js;
    ifs >> js;

    for(auto it = js.begin(); it != js.end(); it++)
    {
        std::string ordinalstring = it.key(), name = it.value();

        if(ordinalstring.empty() || name.empty())
            continue;

        try
        {
            u16 ordinal = std::stoi(ordinalstring);
            m[ordinal] = name;
        }
        catch(...)
        {
            continue;
        }
    }

    ifs.close();
}

} // namespace REDasm
