#ifndef LISTINGTEXTRENDERER_H
#define LISTINGTEXTRENDERER_H

#include <QRegularExpression>
#include <QTextCursor>
#include <QFontMetrics>
#include <QFont>
#include "../../redasm/disassembler/listing/listingrenderer.h"

class ListingTextRenderer : public REDasm::ListingRenderer
{
    public:
        typedef std::pair<int, int> Range;

    public:
        ListingTextRenderer(const QFont& font, REDasm::DisassemblerAPI* disassembler);
        virtual ~ListingTextRenderer();

    public:
        REDasm::ListingCursor::Position hitTest(const QPointF& pos, int firstline);
        Range wordHitTest(const QPointF& pos, int firstline);
        void updateWordUnderCursor();
        void toggleCursor();
        void enableCursor();
        void disableCursor();

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);

    private:
        std::string findWordUnderCursor(const std::string &s, const REDasm::ListingCursor::Position& cp, int *pos = NULL);
        void updateWordUnderCursor(const std::string& s, const REDasm::ListingCursor::Position& cp);
        void highlightWords(QTextCursor& textcursor, const REDasm::RendererLine& rl) const;
        void highlightLine(QTextCursor& textcursor) const;
        void renderCursor(QTextCursor& textcursor) const;
        void renderSelection(QTextCursor& textcursor, const REDasm::RendererLine &rl) const;

    private:
        QRegularExpression m_rgxwords;
        QFontMetrics m_fontmetrics;
        bool m_cursoractive;
};

#endif // LISTINGTEXTRENDERER_H
