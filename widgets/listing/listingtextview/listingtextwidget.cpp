#include "listingtextview.h"
#include "../../../renderer/surfacepainter.h"
#include "../../../hooks/disassemblerhooks.h"
#include "../../../redasmsettings.h"
#include "../../../redasmfonts.h"
#include <QScrollBar>
#include <QPushButton>
#include <QtGui>

#define DOCUMENT_WHEEL_UNIT 4

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
QString ListingTextWidget::currentLabel(rd_address* address) const { return m_surface ? m_surface->getCurrentLabel(address) : QString(); }
rd_address ListingTextWidget::currentAddress() const { return m_surface ? m_surface->currentAddress() : RD_NVAL; }

void ListingTextWidget::setContext(const RDContextPtr& ctx)
{
    m_context = ctx;
    m_document = RDContext_GetDocument(ctx.get());

    m_surface = new SurfacePainter(m_context, RendererFlags_CenterOnCursor, this);
    connect(m_surface, &SurfacePainter::renderCompleted, this, [&]() { this->viewport()->update(); });

    connect(m_surface, &SurfacePainter::addressChanged, this, [&]() {
        this->verticalScrollBar()->blockSignals(true);
        this->verticalScrollBar()->setSliderPosition(static_cast<int>(m_surface->currentAddress()));
        this->verticalScrollBar()->blockSignals(false);
    });

    connect(this->verticalScrollBar(), &QScrollBar::actionTriggered, this, [&](int action) {
        if(!m_surface) return;

        switch(action) {
            case QScrollBar::SliderSingleStepAdd: m_surface->scroll(m_surface->currentAddress() + 1, 0); break;
            case QScrollBar::SliderSingleStepSub: m_surface->scroll(m_surface->currentAddress() - 1, 0); break;
            case QScrollBar::SliderMove: m_surface->goTo(static_cast<rd_address>(this->verticalScrollBar()->sliderPosition())); break;
            default: break;
        }
    });

    this->adjustScrollBars();
    m_disassemblerpopup = new ListingPopup(m_context, this);
    m_surface->activateCursor(true);
}

bool ListingTextWidget::goTo(rd_address address) { return m_surface ? m_surface->goTo(address) : false; }
bool ListingTextWidget::seek(rd_address address) { return m_surface ? m_surface->seek(address) : false; }
void ListingTextWidget::goBack() { if(m_surface) m_surface->goBack(); }
void ListingTextWidget::goForward() { if(m_surface) m_surface->goForward(); }
bool ListingTextWidget::hasSelection() const { return m_surface ? m_surface->hasSelection() : false;  }
void ListingTextWidget::copy() const { if(m_surface) m_surface->copy(); }
void ListingTextWidget::linkTo(ISurface* s) { if(m_surface) m_surface->linkTo(s->surface()); }
void ListingTextWidget::unlink() { if(m_surface) m_surface->unlink(); }
void ListingTextWidget::scrollContentsBy(int dx, int) { if(m_surface) m_surface->scroll(RD_NVAL, -dx); }

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

        if(!ndegrees.isNull())
        {
            rd_offset offset = RD_NVAL;
            int ncols = 0;

            if(ndegrees.y() > 0) offset = m_surface->firstAddress() -DOCUMENT_WHEEL_UNIT;
            else if(ndegrees.y() < 0) offset = m_surface->firstAddress() + DOCUMENT_WHEEL_UNIT;

            if(ndegrees.x() > 0) ncols = -1;
            else if(ndegrees.x() < 0) ncols = 1;

            m_surface->scroll(offset, ncols);
        }

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

    rd_address address;
    QString s = this->currentLabel(&address);
    return !s.isEmpty() ? this->goTo(address) : false;
}

void ListingTextWidget::adjustScrollBars()
{
    if(!m_context || !m_surface) return;

    rd_address start = 0, end = 0;
    m_surface->getScrollRange(&start, &end);

    this->verticalScrollBar()->setMinimum(static_cast<int>(start));
    this->verticalScrollBar()->setMaximum(static_cast<int>(end));
    this->horizontalScrollBar()->setMaximum(this->width() * 2);
}

void ListingTextWidget::showPopup(const QPointF& pt)
{
    if(!m_surface) return;

    rd_address address;

    if(m_surface->getLabelAt(pt, &address) && !m_surface->contains(address))
        m_disassemblerpopup->popup(address);
    else
        m_disassemblerpopup->hide();
}
