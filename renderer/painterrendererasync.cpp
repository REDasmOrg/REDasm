#include "painterrendererasync.h"
#include <QPainter>
#include <QWidget>

PainterRendererAsync::PainterRendererAsync(const RDDisassemblerPtr& disassembler, rd_flag flags, QObject* parent): RendererAsync(disassembler, parent)
{
    m_painterrenderer = new PainterRenderer(disassembler, flags, this);
}

void PainterRendererAsync::scheduleImage(size_t first, size_t last)
{
    m_first = first;
    m_last = last;
    this->schedule();
}

PainterRenderer* PainterRendererAsync::renderer() const { return m_painterrenderer; }
bool PainterRendererAsync::conditionWait() const { return m_first != m_last; }

void PainterRendererAsync::onRender(QImage* image)
{
    const size_t first = m_first;
    const size_t last = m_last;
    m_first = m_last = RD_NPOS;

    QPainter painter(image);
    painter.setFont(this->widget()->font());
    m_painterrenderer->render(&painter, first, last);
}
