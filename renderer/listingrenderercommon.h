#ifndef LISTINGRENDERERCOMMON_H
#define LISTINGRENDERERCOMMON_H

#include <QFontMetricsF>
#include <QTextCursor>
#include <QFont>
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/disassembler/listing/listingrenderer.h>

class ListingRendererCommon: public REDasm::ListingRenderer
{
    public:
        ListingRendererCommon(REDasm::DisassemblerAPI* disassembler);
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
