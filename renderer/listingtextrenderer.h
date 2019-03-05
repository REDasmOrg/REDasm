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
        virtual ~ListingTextRenderer() = default;
        void setFirstVisibleLine(u64 line);

    public:
        REDasm::ListingCursor::Position hitTest(const QPointF& pos, int firstline);
        std::string getWordUnderCursor(const QPointF& pos, int firstline, int* p = NULL);
        Range wordHitTest(const QPointF& pos, int firstline);
        void highlightWordUnderCursor();
        bool cursorActive() const;
        void toggleCursor();
        void enableCursor();
        void disableCursor();

    protected:
        virtual void renderLine(const REDasm::RendererLine& rl);

    private:
        QFont m_font;
        QFontMetrics m_fontmetrics;
        QTextOption m_textoption;
        QRegularExpression m_rgxwords;
        u64 m_firstline;
        bool m_cursoractive;
};

#endif // LISTINGTEXTRENDERER_H
