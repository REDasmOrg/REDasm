#include "listingtextrenderer.h"
#include "../../themeprovider.h"
#include <QPainter>

ListingTextRenderer::ListingTextRenderer(const QFont &font, REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler), m_cursoractive(false), m_fontmetrics(font) { }
ListingTextRenderer::~ListingTextRenderer() { }
void ListingTextRenderer::toggleCursorActive() { m_cursoractive = !m_cursoractive; }

void ListingTextRenderer::renderText(const REDasm::RendererFormat *rf)
{
    QPainter* painter = reinterpret_cast<QPainter*>(rf->userdata);
    QRectF rect(rf->x, rf->y, this->measureString(rf->text), rf->fontheight);

    if(rf->cursor.highlighted)
    {
        QRect rvp = painter->viewport();
        rvp.moveTo(rf->x, rf->y);
        rvp.setHeight(rf->fontheight);

        painter->fillRect(rvp, THEME_VALUE("highlight"));
    }

    if(!rf->style.empty())
        painter->setPen(THEME_VALUE(QString::fromStdString(rf->style)));
    else
        painter->setPen(Qt::black);

    painter->drawText(rect, Qt::AlignLeft | Qt::AlignTop, QString::fromStdString(rf->text));
}

void ListingTextRenderer::renderCursor(const REDasm::RendererFormat *rf)
{
    if(!m_cursoractive)
        return;

    QRectF r(rf->cursor.column * rf->fontwidth, rf->y, rf->fontwidth, rf->fontheight);
    QPainter* painter = reinterpret_cast<QPainter*>(rf->userdata);

    painter->save();
    painter->fillRect(r, Qt::black);

    if(static_cast<size_t>(rf->cursor.column) < rf->fulltext.size())
    {
        painter->setPen(Qt::white);
        painter->drawText(r, Qt::AlignLeft | Qt::AlignTop, QString(rf->fulltext[rf->cursor.column]));
    }

    painter->restore();
}

void ListingTextRenderer::fontUnit(double *w, double *h) const
{
    if(w)
        *w = m_fontmetrics.width(" ");

    if(h)
        *h = m_fontmetrics.height();
}
