#ifndef LISTINGDOCUMENTRENDERER_H
#define LISTINGDOCUMENTRENDERER_H

#include <QtGlobal>
#include <redasm/disassembler/listing/listingrenderer.h>

class ListingDocumentRenderer: public REDasm::ListingRenderer
{
    public:
        ListingDocumentRenderer(REDasm::DisassemblerAPI* disassembler);
        qreal maxWidth() const;
        virtual ~ListingDocumentRenderer();

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);
        qreal m_maxwidth;
};

#endif // LISTINGDOCUMENTRENDERER_H
