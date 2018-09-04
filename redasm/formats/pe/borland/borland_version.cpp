#include "borland_version.h"
#include <algorithm>

namespace REDasm {

BorlandVersion::BorlandVersion(PackageInfoHeader *packageinfo, const PEResources::ResourceItem &resourceitem, u64 size): m_packageinfo(packageinfo), m_resourceitem(resourceitem), m_size(size)
{

}

bool BorlandVersion::isDelphi() const
{
    return IS_PASCAL(m_packageinfo) || IS_PRE_V4(m_packageinfo);
}

bool BorlandVersion::isTurboCpp() const
{
    return IS_CPP(m_packageinfo);
}

std::string BorlandVersion::getSignature() const
{
    if(IS_PRE_V4(m_packageinfo))
        return "delphi3";

    if(this->contains("System.SysUtils"))
        return "delphiXE2_6";

    if(this->contains("ExcUtils"))
        return "delphiXE";

    if(this->contains("StrUtils"))
        return "delphi09_10";

    if(this->contains("ImageHlp"))
        return "delphi06";

    if(this->contains("SysInit"))
        return "delphi7";

    return std::string();
}

bool BorlandVersion::contains(const std::string &s) const
{
    const char* fs = s.data();
    char* p = reinterpret_cast<char*>(m_packageinfo);

    return static_cast<size_t>(std::search(p, p + m_size, fs, fs + s.size()) - p) < m_size;
}

} // namespace REDasm
