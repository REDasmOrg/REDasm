#include "listingtextview.h"
#include "../../renderer/surfacerenderer.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../redasmsettings.h"
#include "../../redasmfonts.h"
#include <QScrollBar>
#include <QPushButton>
#include <QtGui>

#define DOCUMENT_WHEEL_LINES  3

ListingTextView::ListingTextView(QWidget *parent): QAbstractScrollArea(parent)
{
    int maxwidth = qApp->primaryScreen()->size().width();
    this->viewport()->setFixedWidth(maxwidth);
    this->setPalette(qApp->palette()); // Don't inherit palette

    QPushButton* tbscreenshot = new QPushButton();
    tbscreenshot->setIcon(FA_ICON(0xf030));
    tbscreenshot->setFlat(true);

    connect(tbscreenshot, &QPushButton::clicked, this, [&]() {
        if(!m_pixmap.isNull()) qApp->clipboard()->setPixmap(m_pixmap);
    });

    this->setCornerWidget(tbscreenshot);
    this->setFont(REDasmSettings::font());
    this->setCursor(Qt::ArrowCursor);
    this->setFrameStyle(QFrame::NoFrame);
    this->setContextMenuPolicy(Qt::CustomContextMenu);
    this->setFocusPolicy(Qt::StrongFocus);
    this->verticalScrollBar()->setMinimum(0);
    this->verticalScrollBar()->setValue(0);
    this->verticalScrollBar()->setSingleStep(1);
    this->verticalScrollBar()->setPageStep(1);
    this->horizontalScrollBar()->setSingleStep(this->fontMetrics().boundingRect(" ").width());
    this->horizontalScrollBar()->setMinimum(0);
    this->horizontalScrollBar()->setValue(0);
    this->horizontalScrollBar()->setMaximum(maxwidth);
}

RDCursor* ListingTextView::cursor() const { return m_rasync ? m_rasync->renderer()->cursor() : nullptr; }
QWidget* ListingTextView::widget() { return this; }

QString ListingTextView::currentWord() const
{
    if(!m_renderer) return QString();
    const char* cw = RDSurface_GetCurrentWord(m_renderer->surface());
    return cw ? cw : QString();
}

const RDContextPtr& ListingTextView::context() const { return m_context; }
const RDCursorPos* ListingTextView::currentPosition() const { return m_renderer ? RDSurface_GetPosition(m_renderer->surface()) : nullptr; }
const RDCursorPos* ListingTextView::currentSelection() const { return m_renderer ? RDSurface_GetSelection(m_renderer->surface()) : nullptr; }
bool ListingTextView::canGoBack() const { return m_renderer ? RDSurface_CanGoBack(m_renderer->surface()) : false; }
bool ListingTextView::canGoForward() const { return m_renderer ? RDSurface_CanGoForward(m_renderer->surface()) : false; }

bool ListingTextView::getCurrentItem(RDDocumentItem* item) const
{
    if(!m_renderer) return false;
    return RDSurface_GetCurrentItem(m_renderer->surface(), item);
}

bool ListingTextView::getSelectedSymbol(RDSymbol* symbol) const
{
    if(!m_renderer) return false;
    return RDSurface_GetSelectedSymbol(m_renderer->surface(), symbol);
}

bool ListingTextView::ownsCursor(const RDCursor* cursor) const { return m_rasync ? (m_rasync->renderer()->cursor() == cursor) : false; }

void ListingTextView::setContext(const RDContextPtr& disassembler)
{
    m_context = disassembler;
    m_document = RDContext_GetDocument(disassembler.get());

    m_renderer = new SurfaceRenderer(m_context, this);
    connect(m_renderer, &SurfaceRenderer::renderCompleted, this, [&]() { this->viewport()->update(); });

    m_contextmenu = DisassemblerHooks::instance()->createActions(this);
    connect(this, &ListingTextView::customContextMenuRequested, this, [&](const QPoint&) {
        if(RDDocument_GetSize(m_document)) m_contextmenu->popup(QCursor::pos());
    });

    m_disassemblerpopup = new DisassemblerPopup(m_context, this);
}

bool ListingTextView::goToAddress(rd_address address)
{
    if(!m_renderer) return false;
    return RDSurface_GoToAddress(m_renderer->surface(), address);
}

bool ListingTextView::goTo(const RDDocumentItem& item)
{
    if(!m_renderer) return false;
    return RDSurface_GoTo(m_renderer->surface(), &item);
}

void ListingTextView::goBack() { if(m_renderer) RDSurface_GoBack(m_renderer->surface()); }
void ListingTextView::goForward() { if(m_renderer) RDSurface_GoForward(m_renderer->surface()); }
bool ListingTextView::hasSelection() const { return m_renderer ? RDSurface_HasSelection(m_renderer->surface()) : false;  }
void ListingTextView::copy() const { if(m_rasync) m_rasync->renderer()->copy(); }

void ListingTextView::scrollContentsBy(int dx, int dy)
{
}

void ListingTextView::focusInEvent(QFocusEvent* event)
{
    if(m_renderer) RDSurface_EnableCursor(m_renderer->surface());
    QAbstractScrollArea::focusInEvent(event);
}

void ListingTextView::focusOutEvent(QFocusEvent* event)
{
    if(m_renderer) RDSurface_DisableCursor(m_renderer->surface());
    QAbstractScrollArea::focusOutEvent(event);
}

void ListingTextView::paintEvent(QPaintEvent *event)
{
    if(!m_renderer)
    {
        QWidget::paintEvent(event);
        return;
    }

    QPainter painter(this->viewport());
    painter.drawPixmap(QPoint(0, 0), m_renderer->pixmap());
}

void ListingTextView::resizeEvent(QResizeEvent *event)
{
    QAbstractScrollArea::resizeEvent(event);
    //this->adjustScrollBars();
    if(m_renderer) m_renderer->resize();
}

void ListingTextView::mousePressEvent(QMouseEvent *event)
{
    if(event->button() == Qt::LeftButton)
    {
        m_renderer->moveTo(event->pos());
        event->accept();
        return;
    }

    QWidget::mousePressEvent(event);
}

void ListingTextView::mouseMoveEvent(QMouseEvent *event)
{
    if(m_renderer && (event->buttons() == Qt::LeftButton))
    {
        m_renderer->select(event->pos());
        event->accept();
        return;
    }

    QWidget::mouseMoveEvent(event);
}

void ListingTextView::mouseDoubleClickEvent(QMouseEvent *event)
{
    if(event->button() == Qt::LeftButton)
    {
        if(!this->followUnderCursor())
        {
            //m_rasync->renderer()->selectWordFromPoint(e->pos());
        }

        event->accept();
        return;
    }

    QAbstractScrollArea::mouseDoubleClickEvent(event);
}

void ListingTextView::wheelEvent(QWheelEvent *event)
{
    if(m_renderer)
    {
        QPoint ndegrees = event->angleDelta() / 8;
        QPoint nsteps = ndegrees / 15;
        m_renderer->scroll(-nsteps.y() * DOCUMENT_WHEEL_LINES, nsteps.x());
        event->accept();
        return;
    }

    QAbstractScrollArea::wheelEvent(event);
}

void ListingTextView::keyPressEvent(QKeyEvent *event)
{
    if(!m_renderer)
    {
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }

    const RDCursorPos* pos = RDSurface_GetPosition(m_renderer->surface());

    if(event->matches(QKeySequence::MoveToNextChar) || event->matches(QKeySequence::SelectNextChar))
    {
        if(event->matches(QKeySequence::MoveToNextChar)) m_renderer->moveTo(pos->row, pos->column + 1);
        else m_renderer->select(pos->row, pos->column + 1);
    }
    else if(event->matches(QKeySequence::MoveToPreviousChar) || event->matches(QKeySequence::SelectPreviousChar))
    {
        if(event->matches(QKeySequence::MoveToPreviousChar)) m_renderer->moveTo(pos->row, pos->column - 1);
        else m_renderer->select(pos->row, pos->column - 1);
    }
    else if(event->matches(QKeySequence::MoveToNextLine) || event->matches(QKeySequence::SelectNextLine))
    {
        int nextline = pos->row + 1;
        if(event->matches(QKeySequence::MoveToNextLine)) m_renderer->moveTo(nextline, pos->column);
        else m_renderer->select(nextline, pos->column);
    }
    else if(event->matches(QKeySequence::MoveToPreviousLine) || event->matches(QKeySequence::SelectPreviousLine))
    {
        int prevline = pos->row - 1;
        if(event->matches(QKeySequence::MoveToPreviousLine)) m_renderer->moveTo(prevline, pos->column);
        else m_renderer->select(prevline, pos->column);
    }
    else if(event->matches(QKeySequence::MoveToNextPage) || event->matches(QKeySequence::SelectNextPage))
    {
        if(event->matches(QKeySequence::MoveToNextPage)) RDSurface_Scroll(m_renderer->surface(), m_renderer->rows(), 0);
        else RDSurface_Select(m_renderer->surface(), m_renderer->rows(), pos->column);
    }
    else if(event->matches(QKeySequence::MoveToPreviousPage) || event->matches(QKeySequence::SelectPreviousPage))
    {
        if(event->matches(QKeySequence::MoveToPreviousPage)) RDSurface_Scroll(m_renderer->surface(), -m_renderer->rows(), 0);
        else RDSurface_Select(m_renderer->surface(), -m_renderer->rows(), pos->column);
    }
    else if(event->matches(QKeySequence::MoveToStartOfDocument) || event->matches(QKeySequence::SelectStartOfDocument))
    {
        if(event->matches(QKeySequence::MoveToStartOfDocument)) m_renderer->moveTo(0, 0);
        else m_renderer->select(0, 0);
    }
    else if(event->matches(QKeySequence::MoveToEndOfDocument) || event->matches(QKeySequence::SelectEndOfDocument))
    {
        if(event->matches(QKeySequence::MoveToEndOfDocument)) RDSurface_MoveTo(m_renderer->surface(), -1, pos->column);
        else RDSurface_Select(m_renderer->surface(), -1, pos->column);
    }
    else if(event->matches(QKeySequence::MoveToStartOfLine) || event->matches(QKeySequence::SelectStartOfLine))
    {
        if(event->matches(QKeySequence::MoveToStartOfLine)) m_renderer->moveTo(pos->row, 0);
        else m_renderer->select(pos->row, 0);
    }
    else if(event->matches(QKeySequence::MoveToEndOfLine) || event->matches(QKeySequence::SelectEndOfLine))
    {
        if(event->matches(QKeySequence::MoveToEndOfLine)) RDSurface_MoveTo(m_renderer->surface(), pos->row, -1);
        else RDSurface_Select(m_renderer->surface(), pos->row, -1);
    }
    else if(event->key() == Qt::Key_Space) emit switchView();
    else QAbstractScrollArea::keyPressEvent(event);
}

bool ListingTextView::event(QEvent *event)
{
    if(m_context && !RDContext_IsBusy(m_context.get()) && (event->type() == QEvent::ToolTip))
    {
        QHelpEvent* helpevent = static_cast<QHelpEvent*>(event);
        this->showPopup(helpevent->pos());
        return true;
    }

    return QAbstractScrollArea::event(event);
}

bool ListingTextView::followUnderCursor()
{
    if(!m_renderer) return false;

    RDSymbol symbol;
    if(!this->getSelectedSymbol(&symbol)) return false;
    return this->goToAddress(symbol.address);
}

void ListingTextView::adjustScrollBars()
{
    if(!m_context) return;

    // QScrollBar* vscrollbar = this->verticalScrollBar();
    // size_t vl = this->visibleLines(), count = RDDocument_ItemsCount(m_document);

    // if(count <= vl) vscrollbar->setMaximum(static_cast<int>(count));
    // else vscrollbar->setMaximum(static_cast<int>(count - vl + 1));
}

void ListingTextView::showPopup(const QPointF& pt)
{
    if(!RDDocument_GetSize(m_document)) return;

    // QString word = m_rasync->renderer()->getWordFromPoint(pt, nullptr);

    // if(!word.isEmpty())
    // {
    //     RDCursorPos pos = m_rasync->renderer()->hitTest(pt);
    //     m_disassemblerpopup->popup(word, pos.row);
    //     return;
    // }

    // m_disassemblerpopup->hide();
}
