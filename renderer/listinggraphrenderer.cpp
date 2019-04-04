#include "listinggraphrenderer.h"
#include "listingrenderercommon.h"

ListingGraphRenderer::ListingGraphRenderer(REDasm::DisassemblerAPI *disassembler): ListingPopupRenderer(disassembler) { this->setFlags(ListingGraphRenderer::HideSegmentName); }
