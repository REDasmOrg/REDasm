#ifndef LISTINGTEXTRENDERER_H
#define LISTINGTEXTRENDERER_H

#include <QFont>
#include <QFontMetrics>
#include "../../redasm/disassembler/listing/listingrenderer.h"

class ListingTextRenderer : public REDasm::ListingRenderer
{
    public:
        ListingTextRenderer(const QFont& font, REDasm::DisassemblerAPI* disassembler);
        virtual void renderText(const REDasm::RendererFormat* rf);

    protected:
        virtual void fontUnit(double* w = NULL, double* h = NULL) const;

    private:
        QFontMetrics m_fontmetrics;
};

#endif // LISTINGTEXTRENDERER_H
