#pragma once

#include "idisassemblercommand.h"

class ICommandTab
{
    public:
        virtual IDisassemblerCommand* command() const = 0;
        virtual QWidget* widget() = 0;
};
