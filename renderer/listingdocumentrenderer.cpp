#include "listingdocumentrenderer.h"
#include "../convert.h"
#include <QTextDocument>
#include <QTextOption>

ListingDocumentRenderer::ListingDocumentRenderer(): ListingRendererCommon() { this->setFlags(REDasm::ListingRendererFlags::HideSegmentAndAddress); }

void ListingDocumentRenderer::renderLine(const REDasm::RendererLine &rl)
{
    QTextDocument* textdocument = static_cast<QTextDocument*>(rl.userdata);
    QTextCursor textcursor(textdocument);

    m_maxwidth = std::max(m_maxwidth, m_fontmetrics.boundingRect(Convert::to_qstring(rl.text)).width());
    this->insertText(rl, &textcursor);
}
