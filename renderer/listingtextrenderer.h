#ifndef LISTINGTEXTRENDERER_H
#define LISTINGTEXTRENDERER_H

#include <QRegularExpression>
#include <QTextOption>
#include <QFontMetrics>
#include <QFont>
#include <redasm/disassembler/listing/listingrenderer.h>

class ListingTextRenderer: public REDasm::ListingRenderer
{
    public:

    public:
        ListingTextRenderer(const QFont& font, REDasm::DisassemblerAPI* disassembler);
        virtual ~ListingTextRenderer() = default;
        int maxWidth() const;
        void setFirstVisibleLine(u64 line);

    public:
        REDasm::ListingCursor::Position hitTest(const QPointF& pos);
        REDasm::ListingRenderer::Range wordHitTest(const QPointF& pos);
        std::string getWordFromPos(const QPointF& pos, Range *wordpos = nullptr);

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);

    private:
        QFontMetricsF m_fontmetrics;
        u64 m_firstline;
        qreal m_maxwidth;
};

#endif // LISTINGTEXTRENDERER_H
