#ifndef PEDOTNET_H
#define PEDOTNET_H

#include "dotnet_header.h"

namespace REDasm {

class PeDotNet
{
    private:
        PeDotNet();

    public:
        static std::string getVersion(ImageCor20MetaData *cormetadata);
        static u16 getNumberOfStreams(ImageCor20MetaData* cormetadata);
        static ImageStreamHeader* getStream(ImageCor20MetaData* cormetadata, const std::string &id);
};

} // namespace REDasm

#endif // PEDOTNET_H
