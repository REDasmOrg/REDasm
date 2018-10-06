#ifndef LISTINGRENDERERCOMMON_H
#define LISTINGRENDERERCOMMON_H

#include <QRegularExpression>
#include <QTextDocument>
#include <QTextCursor>
#include "../redasm/disassembler/listing/listingdocument.h"
#include "../redasm/disassembler/listing/listingrenderer.h"

class ListingRendererCommon
{
    public:
        ListingRendererCommon(QTextDocument* textdocument, REDasm::ListingDocument* document);
        void insertLine(const REDasm::RendererLine& rl, bool showcursor = false);
        void insertText(const REDasm::RendererLine& rl, bool showcursor = false);
        void insertHtmlLine(const REDasm::RendererLine& rl);
        void insertHtmlText(const REDasm::RendererLine& rl);

    private:
        QString foregroundHtml(const std::string& s, const std::string& style, const REDasm::RendererLine &rl) const;
        QString wordsToSpan(const std::string& s, const REDasm::RendererLine &rl) const;

    private:
        void showCursor();
        void highlightSelection(const REDasm::RendererLine& rl);
        void highlightWords(const REDasm::RendererLine& rl);
        void highlightLine();

    private:
        QTextDocument* m_textdocument;
        QTextCursor m_textcursor;
        REDasm::ListingDocument* m_document;
        QRegularExpression m_rgxwords;
};

#endif // LISTINGRENDERERCOMMON_H
