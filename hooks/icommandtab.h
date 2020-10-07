#pragma once

#include "icommand.h"

class ICommandTab
{
    public:
        virtual ICommand* command() const = 0;
        virtual QWidget* widget() = 0;
};
