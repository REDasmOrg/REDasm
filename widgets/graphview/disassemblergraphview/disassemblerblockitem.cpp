#include "disassemblerblockitem.h"
#include "../../../renderer/listinggraphrenderer.h"
#include "../../../redasmsettings.h"
#include <QApplication>
#include <QFontMetrics>
#include <QPainter>

#define BLOCK_MARGIN 4
#define BLOCK_MARGINS -BLOCK_MARGIN, 0, BLOCK_MARGIN, BLOCK_MARGIN

DisassemblerBlockItem::DisassemblerBlockItem(const REDasm::Graphing::FunctionBasicBlock *fbb, REDasm::DisassemblerAPI *disassembler, QWidget *parent) : GraphViewItem(parent), m_basicblock(fbb), m_disassembler(disassembler)
{
    this->setupDocument();
    ListingGraphRenderer renderer(disassembler);
    renderer.render(fbb->startidx, fbb->count(), &m_document);
    m_document.adjustSize();

    QFontMetrics fm(m_document.defaultFont());
    m_charheight = fm.height();
}

bool DisassemblerBlockItem::hasIndex(s64 index) const { return m_basicblock->contains(index); }

QSize DisassemblerBlockItem::size() const
{
    QSize dsz = this->documentSize();
    dsz.rwidth() += (BLOCK_MARGIN * 2);
    dsz.rheight() += (BLOCK_MARGIN * 2);
    return dsz;
}

QSize DisassemblerBlockItem::documentSize() const
{
    return { static_cast<int>(m_document.size().width()),
             static_cast<int>(m_charheight * m_basicblock->count()) };
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
    REDasmSettings settings;
    QFont font = settings.currentFont();
    font.setPointSize(settings.currentFontSize());

    QTextOption textoption;
    textoption.setWrapMode(QTextOption::NoWrap);

    m_document.setDefaultFont(font);
    m_document.setDefaultTextOption(textoption);
    m_document.setUndoRedoEnabled(false);
}
