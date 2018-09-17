#ifndef LISTINGTEXTRENDERER_H
#define LISTINGTEXTRENDERER_H

#include <QRegularExpression>
#include <QTextCursor>
#include <QScrollBar>
#include <QFontMetrics>
#include <QFont>
#include "../../redasm/disassembler/listing/listingrenderer.h"

class ListingTextRenderer : public REDasm::ListingRenderer
{
    public:
        ListingTextRenderer(const QFont& font, REDasm::DisassemblerAPI* disassembler);
        virtual ~ListingTextRenderer();

    public:
        REDasm::ListingCursor::Position hitTest(const QPointF& pos, QScrollBar* vscrollbar);
        void toggleCursor();

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);

    private:
        void findWordUnderCursor(const QString& s, const REDasm::ListingCursor::Position& cp);
        void highlightWords(QTextCursor &textcursor, const REDasm::RendererLine& rl) const;
        void highlightLine(QTextCursor& textcursor) const;
        void renderCursor(QTextCursor& textcursor) const;

    private:
        QRegularExpression m_rgxwords;
        QFontMetrics m_fontmetrics;
        bool m_cursoractive;
};

#endif // LISTINGTEXTRENDERER_H
