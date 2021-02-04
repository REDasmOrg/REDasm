#include "listingtextview.h"
#include "../../../renderer/surfacepainter.h"
#include "../../../hooks/disassemblerhooks.h"
#include "../../../redasmsettings.h"
#include "../../../redasmfonts.h"
#include <QScrollBar>
#include <QPushButton>
#include <QtGui>

#define DOCUMENT_WHEEL_LINES 3

ListingTextWidget::ListingTextWidget(QWidget *parent): QAbstractScrollArea(parent)
{
    this->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContents);
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
    this->horizontalScrollBar()->setSingleStep(1);
    this->horizontalScrollBar()->setMinimum(0);
    this->horizontalScrollBar()->setValue(0);
}

QWidget* ListingTextWidget::widget() { return this; }

QString ListingTextWidget::currentWord() const
{
    if(!m_surface) return QString();
    const char* cw = m_surface->getCurrentWord();
    return cw ? cw : QString();
}

const RDContextPtr& ListingTextWidget::context() const { return m_context; }
SurfaceQt* ListingTextWidget::surface() const { return m_surface; }
bool ListingTextWidget::canGoBack() const { return m_surface ? m_surface->canGoBack() : false; }
bool ListingTextWidget::canGoForward() const { return m_surface ? m_surface->canGoForward() : false; }

bool ListingTextWidget::getCurrentItem(RDDocumentItem* item) const
{
    if(!m_surface) return false;
    return m_surface->getCurrentItem(item);
}

bool ListingTextWidget::getCurrentSymbol(RDSymbol* symbol) const
{
    if(!m_surface) return false;
    return m_surface->getCurrentSymbol(symbol);
}

void ListingTextWidget::setContext(const RDContextPtr& ctx)
{
    m_context = ctx;
    m_document = RDContext_GetDocument(ctx.get());

    m_surface = new SurfacePainter(m_context, RendererFlags_CenterOnSurface, this);
    connect(m_surface, &SurfacePainter::renderCompleted, this, [&]() { this->viewport()->update(); });
    connect(m_surface, &SurfacePainter::scrollChanged, this, [&]() { this->adjustScrollBars(); });

    connect(m_surface, &SurfacePainter::positionChanged, this, [&]() {
        this->verticalScrollBar()->blockSignals(true);
        this->verticalScrollBar()->setSliderPosition(m_surface->scrollValue());
        this->verticalScrollBar()->blockSignals(false);
    });

    this->adjustScrollBars();

    m_disassemblerpopup = new ListingPopup(m_context, this);
    m_surface->activateCursor(true);
}

bool ListingTextWidget::goToAddress(rd_address address)
{
    if(!m_surface) return false;
    return m_surface->goToAddress(address);
}

bool ListingTextWidget::goTo(const RDDocumentItem* item) { return m_surface ? m_surface->goTo(item) : false; }
bool ListingTextWidget::seek(const RDDocumentItem* item) { return m_surface ? m_surface->seek(item) : false; }
void ListingTextWidget::goBack() { if(m_surface) m_surface->goBack(); }
void ListingTextWidget::goForward() { if(m_surface) m_surface->goForward(); }
bool ListingTextWidget::hasSelection() const { return m_surface ? m_surface->hasSelection() : false;  }
void ListingTextWidget::copy() const { if(m_surface) m_surface->copy(); }
void ListingTextWidget::linkTo(ISurface* s) { if(m_surface) m_surface->linkTo(s->surface()); }
void ListingTextWidget::unlink() { if(m_surface) m_surface->unlink(); }

void ListingTextWidget::scrollContentsBy(int dx, int dy)
{
    if(m_surface) m_surface->scroll(-dy, -dx);
}

void ListingTextWidget::focusInEvent(QFocusEvent* event)
{
    if(m_surface) m_surface->activateCursor(true);
    QAbstractScrollArea::focusInEvent(event);
}

void ListingTextWidget::focusOutEvent(QFocusEvent* event)
{
    if(m_surface) m_surface->activateCursor(false);
    QAbstractScrollArea::focusOutEvent(event);
}

void ListingTextWidget::paintEvent(QPaintEvent *event)
{
    if(!m_surface)
    {
        QWidget::paintEvent(event);
        return;
    }

    QPainter painter(this->viewport());
    painter.drawPixmap(QPoint(0, 0), m_surface->pixmap());
}

void ListingTextWidget::resizeEvent(QResizeEvent *event)
{
    QAbstractScrollArea::resizeEvent(event);
    if(m_surface) m_surface->resize();
    this->adjustScrollBars();
}

void ListingTextWidget::mousePressEvent(QMouseEvent *event)
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

void ListingTextWidget::mouseMoveEvent(QMouseEvent *event)
{
    if(m_surface && (event->buttons() == Qt::LeftButton))
    {
        m_surface->select(event->pos());
        event->accept();
        return;
    }

    QWidget::mouseMoveEvent(event);
}

void ListingTextWidget::mouseDoubleClickEvent(QMouseEvent *event)
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

void ListingTextWidget::wheelEvent(QWheelEvent *event)
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

void ListingTextWidget::keyPressEvent(QKeyEvent *event)
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
    else if(event->key() == Qt::Key_Space) Q_EMIT switchView();
    else QAbstractScrollArea::keyPressEvent(event);
}

bool ListingTextWidget::event(QEvent *event)
{
    if(m_context && !RDContext_IsBusy(m_context.get()) && (event->type() == QEvent::ToolTip))
    {
        QHelpEvent* helpevent = static_cast<QHelpEvent*>(event);
        this->showPopup(helpevent->pos());
        return true;
    }

    return QAbstractScrollArea::event(event);
}

bool ListingTextWidget::followUnderCursor()
{
    if(!m_surface) return false;

    RDSymbol symbol;
    if(!this->getCurrentSymbol(&symbol)) return false;
    return this->goToAddress(symbol.address);
}

void ListingTextWidget::adjustScrollBars()
{
    if(!m_context || !m_surface) return;
    this->verticalScrollBar()->setMaximum(m_surface->scrollLength());
    this->horizontalScrollBar()->setMaximum(this->width() * 2);
}

void ListingTextWidget::showPopup(const QPointF& pt)
{
    if(!m_surface || !RDDocument_GetSize(m_document)) return;

    RDSymbol symbol;

    if(m_surface->getSymbolAt(pt, &symbol) && !m_surface->containsAddress(symbol.address))
        m_disassemblerpopup->popup(&symbol);
    else
        m_disassemblerpopup->hide();
}
