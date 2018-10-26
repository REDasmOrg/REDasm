#include "listingpopuprenderer.h"
#include "listingrenderercommon.h"
#include <QTextDocument>
#include <QFontMetrics>

ListingPopupRenderer::ListingPopupRenderer(REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler), m_maxwidth(0)
{
    this->setFlags(ListingPopupRenderer::HideSegmentName | ListingPopupRenderer::HideAddress);
}

int ListingPopupRenderer::maxWidth() const { return m_maxwidth; }
ListingPopupRenderer::~ListingPopupRenderer() { }

void ListingPopupRenderer::renderLine(const REDasm::RendererLine &rl)
{
    QTextDocument* textdocument = static_cast<QTextDocument*>(rl.userdata);
    QFontMetrics fm(textdocument->defaultFont());
    ListingRendererCommon lrc(textdocument, m_document);

    if(rl.index > 0)
    {
        lrc.insertLine(rl);
        m_maxwidth = std::max(m_maxwidth, fm.boundingRect(QString::fromStdString(rl.text)).width());
    }
    else
    {
        lrc.insertText(rl);
        m_maxwidth = fm.boundingRect(QString::fromStdString(rl.text)).width();
    }
}
