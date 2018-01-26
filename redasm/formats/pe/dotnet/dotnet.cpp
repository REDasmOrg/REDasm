#include "dotnet.h"
#include <cstring>

namespace REDasm {

PeDotNet::PeDotNet()
{

}

std::string PeDotNet::getVersion(ImageCor20MetaData *cormetadata)
{
    return std::string(reinterpret_cast<char*>(&cormetadata->VersionString));
}

u16 PeDotNet::getNumberOfStreams(ImageCor20MetaData *cormetadata)
{
    u16* p = reinterpret_cast<u16*>(reinterpret_cast<u8*>(&cormetadata->VersionString) + cormetadata->VersionLength +
                                    sizeof(u16)); // Flags

    return *p;
}

ImageStreamHeader *PeDotNet::getStream(ImageCor20MetaData *cormetadata, const std::string& id)
{
    u16 n = PeDotNet::getNumberOfStreams(cormetadata);
    u8* p = reinterpret_cast<u8*>(&cormetadata->VersionString) + (cormetadata->VersionLength + (sizeof(u16) * 2)); // Flags + NumberOfStreams
    ImageStreamHeader* pstreamheader = reinterpret_cast<ImageStreamHeader*>(p);

    for(u16 i = 0; i < n; i++)
    {
        if(std::string(pstreamheader->szAlignedAnsi) == id)
            return pstreamheader;

        size_t len = std::strlen(pstreamheader->szAlignedAnsi) + 1;
        pstreamheader = reinterpret_cast<ImageStreamHeader*>(reinterpret_cast<u8*>(pstreamheader) +
                                                             ((sizeof(u32) * 2) + REDasm::aligned(len, 4)));
    }

    REDasm::log("Cannot find Stream Id " + REDasm::quoted(id));
    return NULL;
}

} // namespace REDasm
