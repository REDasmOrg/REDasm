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

    public:
        ListingTextRenderer(REDasm::DisassemblerAPI* disassembler);

    public:
        REDasm::ListingCursor::Position hitTest(const QPointF& pos);
        REDasm::ListingRenderer::Range wordHitTest(const QPointF& pos);
        std::string getWordFromPos(const QPointF& pos, Range *wordpos = nullptr);

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);
};

#endif // LISTINGTEXTRENDERER_H
