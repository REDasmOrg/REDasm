#include "listinggraphrenderer.h"
#include "listingrenderercommon.h"
#include <QTextDocument>

ListingGraphRenderer::ListingGraphRenderer(REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler)
{
    this->setFlags(ListingGraphRenderer::HideSegmentName);
}

void ListingGraphRenderer::renderLine(const REDasm::RendererLine &rl)
{
    QTextDocument* textdocument = static_cast<QTextDocument*>(rl.userdata);
    ListingRendererCommon lrc(textdocument, m_document);

    if(!rl.index)
        lrc.insertHtmlText(rl);
    else
        lrc.insertHtmlLine(rl);
}
