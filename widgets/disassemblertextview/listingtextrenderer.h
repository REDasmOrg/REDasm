#ifndef LISTINGTEXTRENDERER_H
#define LISTINGTEXTRENDERER_H

#include <QFont>
#include <QFontMetrics>
#include "../../redasm/disassembler/listing/listingrenderer.h"

class ListingTextRenderer : public REDasm::ListingRenderer
{
    public:
        ListingTextRenderer(const QFont& font, REDasm::DisassemblerAPI* disassembler);
        virtual ~ListingTextRenderer();
        void toggleCursor();

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);

    private:
        void renderCursor(const REDasm::RendererLine &rl);

    private:
        QFontMetrics m_fontmetrics;
        bool m_cursoractive;
};

#endif // LISTINGTEXTRENDERER_H
