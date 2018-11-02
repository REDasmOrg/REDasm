#include "disassemblercolumnview.h"
#include "../../themeprovider.h"
#include <QPainter>

DisassemblerColumnView::DisassemblerColumnView(QWidget *parent) : QWidget(parent), m_disassembler(NULL), m_document(NULL), m_first(-1), m_last(-1)
{
    this->setBackgroundRole(QPalette::Base);
    this->setAutoFillBackground(true);
}

void DisassemblerColumnView::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    m_disassembler = disassembler;
    m_document = disassembler->document();
}

void DisassemblerColumnView::renderArrows(int start, int count)
{
    m_first = start;
    m_last = start + count - 1;

    m_paths.clear();
    m_pathstyle.clear();

    for(int i = 0; i < count; i++, start++)
    {
        if(start >= static_cast<int>(m_document->size()))
            break;

        REDasm::ListingItem* item = m_document->itemAt(start);

        if(item->is(REDasm::ListingItem::InstructionItem))
        {
            REDasm::InstructionPtr instruction = m_document->instruction(item->address);

            if(!instruction->is(REDasm::InstructionTypes::Jump))
                continue;

            this->applyStyle(instruction, start);

            for(address_t target : instruction->targets)
            {
                if(target == instruction->address)
                    continue;

                int idx = m_document->instructionIndex(target);

                if(idx == -1)
                    continue;

                m_paths.insert(qMakePair(start, idx));
            }
        }
        else if(item->is(REDasm::ListingItem::SymbolItem))
        {
            REDasm::SymbolPtr symbol = m_document->symbol(item->address);

            if(!symbol || !symbol->is(REDasm::SymbolTypes::Code))
                continue;

            REDasm::ReferenceVector refs = m_disassembler->getReferences(symbol->address);

            for(address_t ref : refs)
            {
                if(ref == symbol->address)
                    continue;

                int idx = m_document->instructionIndex(ref);

                if(idx == -1)
                    continue;

                this->applyStyle(idx);
                m_paths.insert(qMakePair(idx, start + 1));
            }
        }
    }

    this->update();
}

void DisassemblerColumnView::paintEvent(QPaintEvent*)
{
    if(!m_disassembler || m_paths.empty())
        return;

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    QFontMetrics fm = this->fontMetrics();
    int w = fm.width(" "), h = fm.height(), hl = h / 2, x = this->width() - (w * 2);

    auto list = m_paths.toList();
    std::sort(list.begin(), list.end());

    for(auto it = list.begin(); it != list.end(); it++, x -= w)
    {
        const auto& path = *it;
        int y1 = ((path.first - m_first) * h) + hl;
        int y2 = ((path.second - m_first) * h) + hl;

        QVector<QLine> points;
        points.push_back(QLine(this->width(), y1, x, y1));
        points.push_back(QLine(x, y1, x, y2));
        points.push_back(QLine(x, y2, this->width(), y2));

        painter.setPen(QPen(m_pathstyle[path.first], 2));
        painter.drawLines(points);
        this->fillArrow(&painter, y2, fm);
    }
}

void DisassemblerColumnView::fillArrow(QPainter* painter, int y, const QFontMetrics& fm)
{
    int w = fm.width(" "), hl = fm.height() / 3;

    QPainterPath path;
    path.moveTo(QPoint(this->width() - w, y));
    path.lineTo(QPoint(this->width() - w, y - hl));
    path.lineTo(QPoint(this->width(), y));
    path.lineTo(QPoint(this->width() - w, y + hl));
    path.lineTo(QPoint(this->width() - w, y));

    painter->fillPath(path, painter->pen().brush());
}

void DisassemblerColumnView::applyStyle(const REDasm::InstructionPtr &instruction, int idx)
{
    if(!instruction)
        return;

    if(instruction->is(REDasm::InstructionTypes::Conditional))
        m_pathstyle[idx] = THEME_VALUE("instruction_jmp_c");
    else if(!m_pathstyle.contains(idx))
        m_pathstyle[idx] = THEME_VALUE("instruction_jmp");
}

void DisassemblerColumnView::applyStyle(int idx)
{
    REDasm::ListingItem* item = m_document->itemAt(idx);

    if(item)
        this->applyStyle(m_document->instruction(item->address), idx);
}
