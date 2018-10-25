#ifndef LISTINGPOPUPRENDERER_H
#define LISTINGPOPUPRENDERER_H

#include <QTextOption>
#include <QFont>
#include "../../redasm/disassembler/listing/listingrenderer.h"

class ListingPopupRenderer: public REDasm::ListingRenderer
{
    public:
        ListingPopupRenderer(REDasm::DisassemblerAPI* disassembler);
        virtual ~ListingPopupRenderer();

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);
};

#endif // LISTINGPOPUPRENDERER_H
