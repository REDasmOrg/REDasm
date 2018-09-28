#include "functionblockitem.h"
#include "../../redasm/disassembler/graph/functiongraph.h"
#include <QFontDatabase>

FunctionBlockItem::FunctionBlockItem(REDasm::DisassemblerAPI *disassembler, REDasm::Graphing::Vertex* v, QObject *parent): GraphTextItem(v, parent), m_disassembler(disassembler), m_vertex(v)
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setStyleHint(QFont::TypeWriter);

    m_textdocument.setDefaultFont(font);
    m_renderer = std::make_unique<ListingGraphRenderer>(disassembler);

    REDasm::Graphing::FunctionGraphVertex* fgv = static_cast<REDasm::Graphing::FunctionGraphVertex*>(v);
    m_renderer->render(fgv->startidx, fgv->count(), &m_textdocument);
}
