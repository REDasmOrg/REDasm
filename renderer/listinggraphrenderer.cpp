#include "listinggraphrenderer.h"
#include "listingrenderercommon.h"

ListingGraphRenderer::ListingGraphRenderer(REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler) { }

void ListingGraphRenderer::renderLine(const REDasm::RendererLine &rl)
{
    QTextDocument* textdocument = static_cast<QTextDocument*>(rl.userdata);
    ListingRendererCommon lrc(textdocument, m_document);

    if(!rl.index)
        lrc.insertText(rl);
    else
        lrc.insertLine(rl);
}
