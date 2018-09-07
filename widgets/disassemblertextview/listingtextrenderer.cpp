#include "listingtextrenderer.h"
#include "../../themeprovider.h"
#include <QPainter>

ListingTextRenderer::ListingTextRenderer(const QFont &font, REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler), m_fontmetrics(font)
{

}

void ListingTextRenderer::renderText(const REDasm::RendererFormat *rf)
{
    QPainter* painter = reinterpret_cast<QPainter*>(rf->userdata);
    QRectF rect(rf->x, rf->y, this->measureString(rf->text), rf->fontheight);

    if(!rf->style.empty())
        painter->setPen(THEME_VALUE(QString::fromStdString(rf->style)));
    else
        painter->setPen(Qt::black);

    painter->drawText(rect, Qt::AlignLeft | Qt::AlignTop, QString::fromStdString(rf->text));
}

void ListingTextRenderer::fontUnit(double *w, double *h) const
{
    if(w)
        *w = m_fontmetrics.width(" ");

    if(h)
        *h = m_fontmetrics.height();
}
