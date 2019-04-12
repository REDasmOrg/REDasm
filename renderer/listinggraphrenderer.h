#ifndef LISTINGGRAPHRENDERER_H
#define LISTINGGRAPHRENDERER_H

#include "listingdocumentrenderer.h"

class ListingGraphRenderer: public ListingDocumentRenderer
{
    public:
        ListingGraphRenderer(REDasm::DisassemblerAPI* disassembler);
};

#endif // LISTINGGRAPHRENDERER_H
