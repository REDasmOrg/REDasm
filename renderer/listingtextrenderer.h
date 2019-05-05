#ifndef LISTINGTEXTRENDERER_H
#define LISTINGTEXTRENDERER_H

#include <QRegularExpression>
#include <QTextOption>
#include <QFontMetrics>
#include <QFont>
#include <redasm/disassembler/listing/listingrenderer.h>
#include "listingrenderercommon.h"

class ListingTextRenderer: public ListingRendererCommon
{
    public:
        ListingTextRenderer(REDasm::DisassemblerAPI* disassembler);
        virtual ~ListingTextRenderer() = default;

    protected:
        void renderLine(const REDasm::RendererLine& rl) override;
};

#endif // LISTINGTEXTRENDERER_H
