#ifndef LISTINGRENDERERCOMMON_H
#define LISTINGRENDERERCOMMON_H

#include <QFontMetricsF>
#include <QTextCursor>
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/disassembler/listing/listingrenderer.h>

class ListingRendererCommon
{
    public:
        ListingRendererCommon() = delete;
        static void insertText(const REDasm::RendererLine& rl, QTextCursor* textcursor);
        static void renderText(const REDasm::RendererLine& rl, float x, float y, const QFontMetricsF &fm);

    private:
        QString foregroundHtml(const std::string& s, const std::string& style, const REDasm::RendererLine &rl) const;
        QString wordsToSpan(const std::string& s, const REDasm::RendererLine &rl) const;
};

#endif // LISTINGRENDERERCOMMON_H
