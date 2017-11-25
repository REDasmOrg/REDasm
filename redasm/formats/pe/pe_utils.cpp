#include "pe_utils.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace REDasm {

static bool endsWith(const std::string &str, const std::string &suffix)
{
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

PEUtils::PEUtils()
{

}

std::string PEUtils::importName(std::string library, const std::string &name)
{
    std::transform(library.begin(), library.end(), library.begin(), ::tolower);

    if(!endsWith(library, ".dll"))
        library += ".dll";

    std::stringstream ss;
    ss << library << "_" << name;
    return ss.str();
}

std::string PEUtils::importName(std::string library, s64 ordinal)
{
    std::stringstream ss;
    ss << "Ordinal__" << std::uppercase << std::setw(4) << std::setfill('0') << std::setbase(16) << ordinal;
    return PEUtils::importName(library, ss.str());
}

} // namespace REDasm
