#include "listingtextrenderer.h"
#include "../../themeprovider.h"
#include <QPainter>

ListingTextRenderer::ListingTextRenderer(const QFont &font, REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler), m_fontmetrics(font), m_cursoractive(false) { }
ListingTextRenderer::~ListingTextRenderer() { }
void ListingTextRenderer::toggleCursor() { m_cursoractive = !m_cursoractive; }

void ListingTextRenderer::renderLine(const REDasm::RendererLine &rl)
{
    QPainter* painter = reinterpret_cast<QPainter*>(rl.userdata);
    QRect rvp = painter->viewport();
    rvp.setY(rl.index * m_fontmetrics.height());
    rvp.setHeight(m_fontmetrics.height());

    if(rl.highlighted)
        painter->fillRect(rvp, THEME_VALUE("highlight"));

    rvp.setX(0);

    for(const REDasm::RendererFormat& rf : rl.formats)
    {
        QString s = QString::fromStdString(rf.text);
        rvp.setWidth(m_fontmetrics.horizontalAdvance(s));

        if(!rf.style.empty())
            painter->setPen(THEME_VALUE(QString::fromStdString(rf.style)));
        else
            painter->setPen(Qt::black);

        painter->drawText(rvp, Qt::AlignLeft | Qt::AlignTop, s);
        rvp.setX(rvp.x() + rvp.width());
    }

    if(m_cursoractive && rl.highlighted)
        this->renderCursor(rl);
}

void ListingTextRenderer::renderCursor(const REDasm::RendererLine& rl)
{
    QString s = QString::fromStdString(rl.text());
    REDasm::ListingCursor* cur = m_document->cursor();
    QRectF r;

    if(cur->currentColumn() < s.length())
        r.setX(m_fontmetrics.horizontalAdvance(s, cur->currentColumn()));
    else
        r.setX(cur->currentColumn() * m_fontmetrics.averageCharWidth());

    r.setY(rl.index * m_fontmetrics.height());
    r.setHeight(m_fontmetrics.height());
    r.setWidth(m_fontmetrics.averageCharWidth());

    QPainter* painter = reinterpret_cast<QPainter*>(rl.userdata);
    painter->fillRect(r, Qt::black);

    if(cur->currentColumn() < s.length())
    {
        painter->setPen(Qt::white);
        painter->drawText(r, Qt::AlignLeft | Qt::AlignTop, s.mid(cur->currentColumn(), 1));
    }
}
