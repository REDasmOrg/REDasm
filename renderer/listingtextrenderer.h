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

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);
};

#endif // LISTINGTEXTRENDERER_H
