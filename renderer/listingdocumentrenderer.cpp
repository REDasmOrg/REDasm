#include "listingdocumentrenderer.h"
#include "listingrenderercommon.h"
#include <QTextDocument>
#include <QTextOption>
#include <QFont>

ListingDocumentRenderer::ListingDocumentRenderer(REDasm::DisassemblerAPI* disassembler): REDasm::ListingRenderer(disassembler), m_maxwidth(0)
{
    this->setFlags(ListingDocumentRenderer::HideSegmentName | ListingDocumentRenderer::HideAddress);
}

qreal ListingDocumentRenderer::maxWidth() const { return m_maxwidth; }
ListingDocumentRenderer::~ListingDocumentRenderer() { }

void ListingDocumentRenderer::renderLine(const REDasm::RendererLine &rl)
{
    QTextDocument* textdocument = static_cast<QTextDocument*>(rl.userdata);
    QFontMetricsF fm(textdocument->defaultFont());
    QTextCursor textcursor(textdocument);

    m_maxwidth = std::max(m_maxwidth, fm.boundingRect(QString::fromStdString(rl.text)).width());
    ListingRendererCommon::insertText(rl, &textcursor);
}
