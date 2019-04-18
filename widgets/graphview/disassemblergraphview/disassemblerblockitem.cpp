#include "disassemblerblockitem.h"
#include "../../../redasmsettings.h"
#include <QApplication>
#include <QFontMetricsF>
#include <QPainter>
#include <QDebug>

#define BLOCK_MARGIN 4
#define BLOCK_MARGINS -BLOCK_MARGIN, 0, BLOCK_MARGIN, BLOCK_MARGIN

DisassemblerBlockItem::DisassemblerBlockItem(const REDasm::Graphing::FunctionBasicBlock *fbb, const REDasm::DisassemblerPtr &disassembler, const REDasm::Graphing::Node &node, QWidget *parent) : GraphViewItem(node, parent), m_basicblock(fbb), m_disassembler(disassembler)
{
    this->setupDocument();

    m_renderer = std::make_unique<ListingDocumentRenderer>(disassembler.get());
    m_renderer->setFlags(ListingDocumentRenderer::HideSegmentName);
    this->invalidate(false);

    QFontMetricsF fm(m_document.defaultFont());
    m_charheight = fm.height();

    EVENT_CONNECT(m_disassembler->document()->cursor(), positionChanged, this, [&]() {
        if(!m_basicblock->contains(m_disassembler->document()->cursor()->currentLine()))
            return;

        this->invalidate();
    });
}

DisassemblerBlockItem::~DisassemblerBlockItem() { EVENT_DISCONNECT(m_disassembler->document()->cursor(), positionChanged, this); }
bool DisassemblerBlockItem::hasIndex(s64 index) const { return m_basicblock->contains(index); }
QSize DisassemblerBlockItem::size() const { return this->documentSize(); }

void DisassemblerBlockItem::mousePressEvent(QMouseEvent *e)
{
    int line = m_basicblock->startidx + std::floor(e->localPos().y() / m_charheight);
    REDasm::ListingCursor* cursor = m_disassembler->document()->cursor();
    cursor->set(line);
}

void DisassemblerBlockItem::invalidate(bool notify)
{
    m_document.clear();
    m_renderer->render(m_basicblock->startidx, m_basicblock->count(), &m_document);
    m_document.adjustSize();

    GraphViewItem::invalidate(notify);
}

QSize DisassemblerBlockItem::documentSize() const
{
    return { static_cast<int>(m_document.size().width()),
             static_cast<int>(std::ceil(m_charheight * m_basicblock->count())) };
}

void DisassemblerBlockItem::render(QPainter *painter)
{
    QRect r(QPoint(0, 0), this->documentSize());
    r.adjust(BLOCK_MARGINS);

    QColor shadow = painter->pen().color();
    shadow.setAlpha(180);

    painter->save();
        painter->translate(this->position());
        painter->fillRect(r.adjusted(0, 0, BLOCK_MARGIN, BLOCK_MARGIN), shadow);
        painter->fillRect(r, qApp->palette().base());
        m_document.drawContents(painter);
        painter->drawRect(r);
    painter->restore();
}

void DisassemblerBlockItem::setupDocument()
{
    QTextOption textoption;
    textoption.setWrapMode(QTextOption::NoWrap);

    m_document.setDefaultFont(REDasmSettings::font());
    m_document.setDefaultTextOption(textoption);
    m_document.setUndoRedoEnabled(false);
}
