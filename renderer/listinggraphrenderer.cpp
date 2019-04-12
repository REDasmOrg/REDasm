#include "listinggraphrenderer.h"
#include "listingrenderercommon.h"

ListingGraphRenderer::ListingGraphRenderer(REDasm::DisassemblerAPI *disassembler): ListingDocumentRenderer(disassembler)
{
    this->setFlags(ListingGraphRenderer::HideSegmentName);
}
