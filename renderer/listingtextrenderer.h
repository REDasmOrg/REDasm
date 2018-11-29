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
        typedef std::pair<int, int> Range;

    public:
        ListingTextRenderer(const QFont& font, REDasm::DisassemblerAPI* disassembler);

    public:
        REDasm::ListingCursor::Position hitTest(const QPointF& pos, int firstline);
        std::string getWordUnderCursor(const QPointF& pos, int firstline, int* p = NULL);
        Range wordHitTest(const QPointF& pos, int firstline);
        void highlightWordUnderCursor();
        void toggleCursor();
        void enableCursor();
        void disableCursor();

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);

    private:
        std::string findWordUnderCursor(const std::string &s, const REDasm::ListingCursor::Position& cp, int *pos = NULL);

    private:
        QFont m_font;
        QFontMetrics m_fontmetrics;
        QTextOption m_textoption;
        QRegularExpression m_rgxwords;
        bool m_cursoractive;
};

#endif // LISTINGTEXTRENDERER_H
