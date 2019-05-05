#ifndef LISTINGRENDERERCOMMON_H
#define LISTINGRENDERERCOMMON_H

#include <QFontMetricsF>
#include <QTextCursor>
#include <QHash>
#include <QFont>
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/disassembler/listing/listingrenderer.h>

#define CURSOR_BLINK_INTERVAL 500  // 500ms

class ListingRendererCommon: public REDasm::ListingRenderer
{
    public:
        ListingRendererCommon(REDasm::DisassemblerAPI* disassembler);
        virtual ~ListingRendererCommon() = default;
        void moveTo(const QPointF& pos);
        void select(const QPointF& pos);
        REDasm::ListingCursor::Position hitTest(const QPointF& pos);
        REDasm::ListingRenderer::Range wordHitTest(const QPointF& pos);
        std::string getWordFromPos(const QPointF& pos, Range *wordpos = nullptr);
        void selectWordAt(const QPointF &pos);
        void setFirstVisibleLine(u64 line);
        const QFontMetricsF fontMetrics() const;
        qreal maxWidth() const;

    protected:
        void insertText(const REDasm::RendererLine& rl, QTextCursor* textcursor);
        void renderText(const REDasm::RendererLine& rl, float x, float y, const QFontMetricsF &fm);

    protected:
        QFontMetricsF m_fontmetrics;
        qreal m_maxwidth;
        u64 m_firstline;
};

#endif // LISTINGRENDERERCOMMON_H
