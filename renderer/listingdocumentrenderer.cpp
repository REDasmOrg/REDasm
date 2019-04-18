#include "listingdocumentrenderer.h"
#include <QTextDocument>
#include <QTextOption>

ListingDocumentRenderer::ListingDocumentRenderer(REDasm::DisassemblerAPI* disassembler): ListingRendererCommon(disassembler)
{
    this->setFlags(ListingDocumentRenderer::HideSegmentName | ListingDocumentRenderer::HideAddress);
}

void ListingDocumentRenderer::renderLine(const REDasm::RendererLine &rl)
{
    QTextDocument* textdocument = static_cast<QTextDocument*>(rl.userdata);
    QTextCursor textcursor(textdocument);

    m_maxwidth = std::max(m_maxwidth, m_fontmetrics.boundingRect(QString::fromStdString(rl.text)).width());
    this->insertText(rl, &textcursor);
}
