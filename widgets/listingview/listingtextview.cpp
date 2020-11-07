#include "listingtextview.h"
#include "../../renderer/surfacepainter.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../redasmsettings.h"
#include "../../redasmfonts.h"
#include <QScrollBar>
#include <QPushButton>
#include <QtGui>

#define DOCUMENT_WHEEL_LINES 3

ListingTextView::ListingTextView(QWidget *parent): QAbstractScrollArea(parent)
{
    int maxwidth = qApp->primaryScreen()->size().width();
    this->viewport()->setFixedWidth(maxwidth);
    this->setPalette(qApp->palette()); // Don't inherit palette

    QPushButton* tbscreenshot = new QPushButton();
    tbscreenshot->setIcon(FA_ICON(0xf030));
    tbscreenshot->setFlat(true);

    connect(tbscreenshot, &QPushButton::clicked, this, [&]() {
        if(!m_surface || m_surface->pixmap().isNull()) return;
        qApp->clipboard()->setPixmap(m_surface->pixmap());
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

QWidget* ListingTextView::widget() { return this; }

QString ListingTextView::currentWord() const
{
    if(!m_surface) return QString();
    const char* cw = m_surface->getCurrentWord();
    return cw ? cw : QString();
}

const RDContextPtr& ListingTextView::context() const { return m_context; }
const RDSurfacePos* ListingTextView::position() const { return m_surface ? m_surface->position() : nullptr; }
const RDSurfacePos* ListingTextView::selection() const { return m_surface ? m_surface->selection() : nullptr; }
SurfaceQt* ListingTextView::surface() const { return m_surface; }
bool ListingTextView::canGoBack() const { return m_surface ? m_surface->canGoBack() : false; }
bool ListingTextView::canGoForward() const { return m_surface ? m_surface->canGoForward() : false; }

bool ListingTextView::getCurrentItem(RDDocumentItem* item) const
{
    if(!m_surface) return false;
    return m_surface->getCurrentItem(item);
}

bool ListingTextView::getCurrentSymbol(RDSymbol* symbol) const
{
    if(!m_surface) return false;
    return m_surface->getCurrentSymbol(symbol);
}

void ListingTextView::setContext(const RDContextPtr& ctx)
{
    m_context = ctx;
    m_document = RDContext_GetDocument(ctx.get());

    m_surface = new SurfacePainter(m_context, RendererFlags_Normal, this);
    connect(m_surface, &SurfacePainter::renderCompleted, this, [&]() { this->viewport()->update(); });

    m_contextmenu = DisassemblerHooks::instance()->createActions(this);
    connect(this, &ListingTextView::customContextMenuRequested, this, [&](const QPoint&) {
        if(RDDocument_GetSize(m_document)) m_contextmenu->popup(QCursor::pos());
    });

    m_disassemblerpopup = new ListingPopup(m_context, this);
}

bool ListingTextView::goToAddress(rd_address address)
{
    if(!m_surface) return false;
    return m_surface->goToAddress(address);
}

bool ListingTextView::goTo(const RDDocumentItem& item)
{
    if(!m_surface) return false;
    return m_surface->goTo(&item);
}

void ListingTextView::goBack() { if(m_surface) m_surface->goBack(); }
void ListingTextView::goForward() { if(m_surface) m_surface->goForward(); }
bool ListingTextView::hasSelection() const { return m_surface ? m_surface->hasSelection() : false;  }
void ListingTextView::copy() const { if(m_surface) m_surface->copy(); }

void ListingTextView::scrollContentsBy(int dx, int dy)
{
}

void ListingTextView::focusInEvent(QFocusEvent* event)
{
    if(m_surface) m_surface->activateCursor(true);
    QAbstractScrollArea::focusInEvent(event);
}

void ListingTextView::focusOutEvent(QFocusEvent* event)
{
    if(m_surface) m_surface->activateCursor(false);
    QAbstractScrollArea::focusOutEvent(event);
}

void ListingTextView::paintEvent(QPaintEvent *event)
{
    if(!m_surface)
    {
        QWidget::paintEvent(event);
        return;
    }

    QPainter painter(this->viewport());
    painter.drawPixmap(QPoint(0, 0), m_surface->pixmap());
}

void ListingTextView::resizeEvent(QResizeEvent *event)
{
    QAbstractScrollArea::resizeEvent(event);
    //this->adjustScrollBars();
    if(m_surface) m_surface->resize();
}

void ListingTextView::mousePressEvent(QMouseEvent *event)
{
    if(m_surface)
    {
        if(event->button() == Qt::LeftButton) m_surface->moveTo(event->pos());
        else if(event->button() == Qt::BackButton) m_surface->goBack();
        else if(event->button() == Qt::ForwardButton) m_surface->goForward();
        else return;
        event->accept();
    }

    QWidget::mousePressEvent(event);
}

void ListingTextView::mouseMoveEvent(QMouseEvent *event)
{
    if(m_surface && (event->buttons() == Qt::LeftButton))
    {
        m_surface->select(event->pos());
        event->accept();
        return;
    }

    QWidget::mouseMoveEvent(event);
}

void ListingTextView::mouseDoubleClickEvent(QMouseEvent *event)
{
    if(m_surface && (event->button() == Qt::LeftButton))
    {
        if(!this->followUnderCursor())
            m_surface->selectAt(event->pos());

        event->accept();
        return;
    }

    QAbstractScrollArea::mouseDoubleClickEvent(event);
}

void ListingTextView::wheelEvent(QWheelEvent *event)
{
    if(m_surface)
    {
        QPoint ndegrees = event->angleDelta() / 8;
        QPoint nsteps = ndegrees / 15;
        m_surface->scroll(-nsteps.y() * DOCUMENT_WHEEL_LINES, nsteps.x());
        event->accept();
        return;
    }

    QAbstractScrollArea::wheelEvent(event);
}

void ListingTextView::keyPressEvent(QKeyEvent *event)
{
    if(!m_surface)
    {
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }

    const RDSurfacePos* pos = m_surface->position();

    if(event->matches(QKeySequence::MoveToNextChar) || event->matches(QKeySequence::SelectNextChar))
    {
        if(event->matches(QKeySequence::MoveToNextChar)) m_surface->moveTo(pos->row, pos->col + 1);
        else m_surface->select(pos->row, pos->col + 1);
    }
    else if(event->matches(QKeySequence::MoveToPreviousChar) || event->matches(QKeySequence::SelectPreviousChar))
    {
        if(event->matches(QKeySequence::MoveToPreviousChar)) m_surface->moveTo(pos->row, pos->col - 1);
        else m_surface->select(pos->row, pos->col - 1);
    }
    else if(event->matches(QKeySequence::MoveToNextLine) || event->matches(QKeySequence::SelectNextLine))
    {
        int nextline = pos->row + 1;
        if(event->matches(QKeySequence::MoveToNextLine)) m_surface->moveTo(nextline, pos->col);
        else m_surface->select(nextline, pos->col);
    }
    else if(event->matches(QKeySequence::MoveToPreviousLine) || event->matches(QKeySequence::SelectPreviousLine))
    {
        int prevline = pos->row - 1;
        if(event->matches(QKeySequence::MoveToPreviousLine)) m_surface->moveTo(prevline, pos->col);
        else m_surface->select(prevline, pos->col);
    }
    else if(event->matches(QKeySequence::MoveToNextPage) || event->matches(QKeySequence::SelectNextPage))
    {
        if(event->matches(QKeySequence::MoveToNextPage)) m_surface->scroll(m_surface->rows(), 0);
        else m_surface->select(m_surface->rows(), pos->col);
    }
    else if(event->matches(QKeySequence::MoveToPreviousPage) || event->matches(QKeySequence::SelectPreviousPage))
    {
        if(event->matches(QKeySequence::MoveToPreviousPage)) m_surface->scroll(-m_surface->rows(), 0);
        else m_surface->select(-m_surface->rows(), pos->col);
    }
    else if(event->matches(QKeySequence::MoveToStartOfDocument) || event->matches(QKeySequence::SelectStartOfDocument))
    {
        if(event->matches(QKeySequence::MoveToStartOfDocument)) m_surface->moveTo(0, 0);
        else m_surface->select(0, 0);
    }
    else if(event->matches(QKeySequence::MoveToEndOfDocument) || event->matches(QKeySequence::SelectEndOfDocument))
    {
        if(event->matches(QKeySequence::MoveToEndOfDocument)) m_surface->moveTo(-1, pos->col);
        else m_surface->select(-1, pos->col);
    }
    else if(event->matches(QKeySequence::MoveToStartOfLine) || event->matches(QKeySequence::SelectStartOfLine))
    {
        if(event->matches(QKeySequence::MoveToStartOfLine)) m_surface->moveTo(pos->row, 0);
        else m_surface->select(pos->row, 0);
    }
    else if(event->matches(QKeySequence::MoveToEndOfLine) || event->matches(QKeySequence::SelectEndOfLine))
    {
        if(event->matches(QKeySequence::MoveToEndOfLine)) m_surface->moveTo(pos->row, -1);
        else m_surface->select(pos->row, -1);
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
    if(!m_surface) return false;

    RDSymbol symbol;
    if(!this->getCurrentSymbol(&symbol)) return false;
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
    if(!m_surface || !RDDocument_GetSize(m_document)) return;

    RDSymbol symbol;
    if(m_surface->getSymbolAt(pt, &symbol)) m_disassemblerpopup->popup(&symbol);
    else m_disassemblerpopup->hide();
}
