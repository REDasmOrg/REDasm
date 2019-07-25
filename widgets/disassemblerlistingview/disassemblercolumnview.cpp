#include "disassemblercolumnview.h"
#include "../../themeprovider.h"
#include <QPainter>

DisassemblerColumnView::DisassemblerColumnView(QWidget *parent) : QWidget(parent), m_disassembler(nullptr), m_first(-1), m_last(-1)
{
    this->setBackgroundRole(QPalette::Base);
    this->setAutoFillBackground(true);
}

void DisassemblerColumnView::setDisassembler(const REDasm::DisassemblerPtr& disassembler) { m_disassembler = disassembler; }

void DisassemblerColumnView::renderArrows(size_t start, size_t count)
{
    m_first = start;
    m_last = start + count - 1;

    m_paths.clear();
    m_done.clear();

    auto& document = m_disassembler->document();

    for(size_t i = 0; i < count; i++, start++)
    {
        if(start >= document->size())
            break;

        REDasm::ListingItem* item = document->itemAt(start);

        if(item->is(REDasm::ListingItemType::InstructionItem))
        {
            REDasm::CachedInstruction instruction = document->instruction(item->address());

            if(!instruction->is(REDasm::InstructionType::Jump))
                continue;

            REDasm::SortedSet targets = m_disassembler->getTargets(instruction->address);

            for(size_t i = 0; i < targets.size(); i++)
            {
                address_t target = targets[i].toU64();

                if(target == instruction->address)
                    continue;

                size_t idx = document->findInstruction(target);

                if(idx >= document->size())
                    continue;

                this->insertPath(item, start, idx);
            }
        }
        else if(item->is(REDasm::ListingItemType::SymbolItem))
        {
            const REDasm::Symbol* symbol = document->symbol(item->address());

            if(!symbol || !symbol->is(REDasm::SymbolType::Code))
                continue;

            size_t toidx = document->findInstruction(item->address());

            if(toidx >= document->size())
                continue;

            REDasm::SortedSet refs = m_disassembler->getReferences(item->address());

            for(size_t i = 0; i < refs.size(); i++)
            {
                address_t ref = refs[i].toU64();

                if(ref == item->address())
                    continue;

                size_t idx = document->findInstruction(ref);

                if(idx >= document->size())
                    continue;

                this->insertPath(document->itemAt(idx), idx, toidx);
            }
        }
    }

    std::sort(m_paths.begin(), m_paths.end(), [](const ArrowPath& p1, const ArrowPath& p2) -> bool {
        return p1.startidx < p2.startidx;
    });

    this->update();
}

void DisassemblerColumnView::paintEvent(QPaintEvent*)
{
    if(!m_disassembler || m_paths.empty())
        return;

    QPainter painter(this);
    QFontMetrics fm = this->fontMetrics();

#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    int w = fm.horizontalAdvance(" ");
#else
    int w = fm.width(" ");
#endif

    int h = fm.height(), x = this->width() - (w * 2);

    for(auto it = m_paths.begin(); it != m_paths.end(); it++, x -= w)
    {
        const ArrowPath& path = *it;
        int y1 = ((path.startidx - m_first) * h) + (h / 4);
        int y2 = ((path.endidx - m_first) * h) + ((h * 3) / 4);
        int y = ((path.endidx - m_first) * h);
        int penwidth = this->isPathSelected(path) ? 3 : 2;

        if(y2 > (y + (h / 2)))
            y2 -= penwidth;
        else if(y2 < (y + (h / 2)))
            y2 += penwidth;

        QVector<QLine> points;
        points.push_back(QLine(this->width(), y1, x, y1));
        points.push_back(QLine(x, y1, x, y2));
        points.push_back(QLine(x, y2, this->width(), y2));

        Qt::PenStyle penstyle = ((path.startidx < m_first) || (path.endidx > m_last)) ? Qt::DotLine : Qt::SolidLine;

        painter.setPen(QPen(path.color, penwidth, penstyle));
        painter.drawLines(points);

        painter.setPen(QPen(path.color, penwidth, Qt::SolidLine));
        this->fillArrow(&painter, y2, fm);
    }
}

bool DisassemblerColumnView::isPathSelected(const DisassemblerColumnView::ArrowPath &path) const
{
    auto& document = m_disassembler->document();
    u64 line = document->cursor()->currentLine();
    return (line == path.startidx) || (line == path.endidx);
}

void DisassemblerColumnView::fillArrow(QPainter* painter, int y, const QFontMetrics& fm)
{
#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    int w = fm.horizontalAdvance(" ") / 2;
#else
    int w = fm.width(" ") / 2;
#endif

    int hl = fm.height() / 3;

    QPainterPath path;
    path.moveTo(QPoint(this->width() - w, y));
    path.lineTo(QPoint(this->width() - w, y - hl));
    path.lineTo(QPoint(this->width(), y));
    path.lineTo(QPoint(this->width() - w, y + hl));
    path.lineTo(QPoint(this->width() - w, y));

    painter->fillPath(path, painter->pen().brush());
}

void DisassemblerColumnView::insertPath(REDasm::ListingItem* fromitem, u64 fromidx, u64 toidx)
{
    auto& document = m_disassembler->document();
    auto pair = qMakePair(fromidx, toidx);
    REDasm::CachedInstruction frominstruction = document->instruction(fromitem->address());

    if(!frominstruction || !frominstruction->is(REDasm::InstructionType::Jump) || m_done.contains(pair))
        return;

    m_done.insert(pair);

    if(fromidx > toidx) // Loop
    {
        if(frominstruction->is(REDasm::InstructionType::Conditional))
            m_paths.append({ fromidx, toidx, THEME_VALUE("graph_edge_loop_c") });
        else
            m_paths.append({ fromidx, toidx, THEME_VALUE("graph_edge_loop") });

        return;
    }

    if(frominstruction->is(REDasm::InstructionType::Conditional))
        m_paths.append({ fromidx, toidx, THEME_VALUE("graph_edge_false") });
    else
        m_paths.append({ fromidx, toidx, THEME_VALUE("graph_edge") });
}
