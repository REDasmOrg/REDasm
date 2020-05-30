#pragma once

#include <QString>

class ListingItemModel;

class ITableTab
{
    public:
        virtual void toggleFilter() = 0;
        virtual ListingItemModel* model() const = 0;
};
