#ifndef LISTINGGRAPHRENDERER_H
#define LISTINGGRAPHRENDERER_H

#include <QTextDocument>
#include "../../redasm/disassembler/listing/listingrenderer.h"

class ListingGraphRenderer: public REDasm::ListingRenderer
{
    public:
        ListingGraphRenderer(REDasm::DisassemblerAPI* disassembler);

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);
};

#endif // LISTINGGRAPHRENDERER_H
