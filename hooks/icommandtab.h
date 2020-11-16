#pragma once

#include <rdapi/rdapi.h>
#include "icommand.h"

class SurfaceQt;

typedef std::shared_ptr<RDContext> RDContextPtr;

class ISurfaceTab
{
    public:
        virtual SurfaceQt* surface() const = 0;
};
