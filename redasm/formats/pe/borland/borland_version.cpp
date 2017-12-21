#include "borland_version.h"
#include <algorithm>

namespace REDasm {

BorlandVersion::BorlandVersion(PackageInfoHeader *packageinfo, const PEResources::ResourceItem &resourceitem, u64 size): _packageinfo(packageinfo), _resourceitem(resourceitem), _size(size)
{

}

bool BorlandVersion::isDelphi() const
{
    return IS_PASCAL(this->_packageinfo) || IS_PRE_V4(this->_packageinfo);
}

bool BorlandVersion::isTurboCpp() const
{
    return IS_CPP(this->_packageinfo);
}

std::string BorlandVersion::getSignature() const
{
    if(IS_PRE_V4(this->_packageinfo))
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
        return "delphi6";

    return std::string();
}

bool BorlandVersion::contains(const std::string &s) const
{
    const char* fs = s.data();
    char* p = reinterpret_cast<char*>(this->_packageinfo);

    return static_cast<size_t>(std::search(p, p + this->_size, fs, fs + s.size()) - p) < this->_size;
}

} // namespace REDasm
