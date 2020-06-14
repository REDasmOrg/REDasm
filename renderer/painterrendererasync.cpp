#include "painterrendererasync.h"
#include <QPainter>
#include <QWidget>

PainterRendererAsync::PainterRendererAsync(RDDisassembler* disassembler, rd_flag flags, QObject* parent): RendererAsync(parent), PainterRenderer(disassembler, flags) { }

void PainterRendererAsync::scheduleImage(size_t first, size_t last)
{
    m_first = first;
    m_last = last;
    this->schedule();
}

bool PainterRendererAsync::conditionWait() const { return m_first != m_last; }

void PainterRendererAsync::onRender(QImage* image)
{
    const size_t first = m_first;
    const size_t last = m_last;
    m_first = m_last = RD_NPOS;

    QPainter painter(image);
    painter.setFont(this->widget()->font());
    this->render(&painter, first, last);
}
