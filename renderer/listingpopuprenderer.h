#ifndef LISTINGPOPUPRENDERER_H
#define LISTINGPOPUPRENDERER_H

#include <QTextOption>
#include <QFont>
#include "../../redasm/disassembler/listing/listingrenderer.h"

class ListingPopupRenderer: public REDasm::ListingRenderer
{
    public:
        ListingPopupRenderer(REDasm::DisassemblerAPI* disassembler);
        int maxWidth() const;
        virtual ~ListingPopupRenderer();

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);

    private:
        int m_maxwidth;
};

#endif // LISTINGPOPUPRENDERER_H
