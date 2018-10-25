#include "listingpopuprenderer.h"
#include "listingrenderercommon.h"
#include <QTextDocument>

ListingPopupRenderer::ListingPopupRenderer(REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler) { }
ListingPopupRenderer::~ListingPopupRenderer() { }

void ListingPopupRenderer::renderLine(const REDasm::RendererLine &rl)
{
    QTextDocument* textdocument = static_cast<QTextDocument*>(rl.userdata);
    ListingRendererCommon lrc(textdocument, m_document);

    if(rl.index > 0)
        lrc.insertLine(rl);
    else
        lrc.insertText(rl);
}
