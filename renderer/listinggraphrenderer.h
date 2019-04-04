#ifndef LISTINGGRAPHRENDERER_H
#define LISTINGGRAPHRENDERER_H

#include "listingpopuprenderer.h"

class ListingGraphRenderer: public ListingPopupRenderer
{
    public:
        ListingGraphRenderer(REDasm::DisassemblerAPI* disassembler);
};

#endif // LISTINGGRAPHRENDERER_H
