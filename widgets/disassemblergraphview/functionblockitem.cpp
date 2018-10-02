#include "functionblockitem.h"
#include "../../redasm/disassembler/graph/functiongraph.h"
#include <QFontDatabase>

FunctionBlockItem::FunctionBlockItem(REDasm::DisassemblerAPI *disassembler, REDasm::Graphing::NodeData *data, QObject *parent): GraphTextItem(data, parent), m_disassembler(disassembler)
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setStyleHint(QFont::TypeWriter);

    m_textdocument.setDefaultFont(font);
    m_renderer = std::make_unique<ListingGraphRenderer>(disassembler);

    REDasm::Graphing::FunctionGraphData* fgdata = static_cast<REDasm::Graphing::FunctionGraphData*>(data);
    m_renderer->render(fgdata->startidx, fgdata->count(), &m_textdocument);

    QSizeF size = m_textdocument.size();
    data->resize(size.width(), size.height());
}
