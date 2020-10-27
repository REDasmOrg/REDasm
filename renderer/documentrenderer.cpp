#include "documentrenderer.h"
#include "../themeprovider.h"
#include <QApplication>
#include <QTextCursor>
#include <QPalette>
#include <cstring>

DocumentRenderer::DocumentRenderer(QTextDocument* textdocument, const RDContextPtr& ctx, RDCursor* cursor, rd_flag flags): QtRenderer(ctx, cursor, flags), m_textdocument(textdocument) { }
QTextDocument* DocumentRenderer::textDocument() const { return m_textdocument; }
qreal DocumentRenderer::maxWidth() const { return m_maxwidth; }

void DocumentRenderer::render(size_t first, size_t last)
{
//    size_t count = (last - first) + 1;
//    m_maxwidth = 0;
//    m_textdocument->clear();
//
//    RDRenderer_GetItems(m_renderer, first, count, [](const RDRendererItem* item, size_t index, void* userdata) {
//        auto* thethis = reinterpret_cast<DocumentRenderer*>(userdata);
//        thethis->render(item, index);
//    }, this);
}

void DocumentRenderer::render(const RDRendererItem* ritem, size_t index)
{
//    const char* text = RDRendererItem_GetItemText(ritem);
//    m_maxwidth = std::max(m_maxwidth, m_fontmetrics.boundingRect(text).width());
//
//    QTextCursor textcursor(m_textdocument);
//
//    if(index)
//    {
//        textcursor.movePosition(QTextCursor::End);
//        textcursor.insertBlock(QTextBlockFormat());
//    }
//
//    const RDRendererFormat* formats = nullptr;
//    size_t c = RDRendererItem_GetItemFormats(ritem, &formats);
//
//    for(size_t i = 0; i < c; i++)
//    {
//        const RDRendererFormat& rf = formats[i];
//        QTextCharFormat charformat;
//
//        if(rf.fgtheme != Theme_Default)
//        {
//            if((rf.fgtheme == Theme_CursorFg) || (rf.fgtheme == Theme_SelectionFg))
//                charformat.setForeground(qApp->palette().color(QPalette::HighlightedText));
//            else
//                charformat.setForeground(THEME_VALUE(rf.fgtheme));
//        }
//
//        if(rf.bgtheme != Theme_Default)
//        {
//            if(rf.bgtheme == Theme_CursorBg)
//                charformat.setBackground(qApp->palette().color(QPalette::WindowText));
//            else if(rf.bgtheme == Theme_SelectionBg)
//                charformat.setBackground(qApp->palette().color(QPalette::Highlight));
//            else
//                charformat.setBackground(THEME_VALUE(rf.bgtheme));
//        }
//
//        QString chunk = QString::fromLocal8Bit(text + rf.start, static_cast<int>(rf.end - rf.start) + 1);
//        textcursor.insertText(chunk, charformat);
//    }
//
//    if(RDCursor_CurrentLine(m_cursor) != RDRendererItem_GetDocumentIndex(ritem))
//        return;
//
//    QTextBlockFormat blockformat;
//    blockformat.setBackground(THEME_VALUE(Theme_Seek));
//    textcursor.setBlockFormat(blockformat);
}
