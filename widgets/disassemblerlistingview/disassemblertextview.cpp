#include "disassemblertextview.h"
#include "../../models/disassemblermodel.h"
#include <core/plugins/loader.h>
#include <QtWidgets>
#include <QtGui>
#include <cmath>

#define FALLBACK_REFRESH_RATE 60.0 // 60Hz
#define DOCUMENT_IDEAL_SIZE   10
#define DOCUMENT_WHEEL_LINES  3

DisassemblerTextView::DisassemblerTextView(QWidget *parent): QAbstractScrollArea(parent), m_disassembler(nullptr), m_disassemblerpopup(nullptr), m_actions(nullptr), m_refreshtimerid(-1)
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setStyleHint(QFont::TypeWriter);

    int maxwidth = qApp->primaryScreen()->size().width();
    this->viewport()->setFixedWidth(maxwidth);
    this->setPalette(qApp->palette()); // Don't inherit palette

    this->setFont(font);
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

    float refreshfreq = qApp->primaryScreen()->refreshRate();

    if(refreshfreq <= 0)
        refreshfreq = FALLBACK_REFRESH_RATE;

    REDasm::log("Setting refresh rate to " + QString::number(refreshfreq, 'f', 1).toStdString() + "Hz");
    m_refreshrate = std::ceil((1 / refreshfreq) * 1000);
    m_blinktimerid = this->startTimer(CURSOR_BLINK_INTERVAL);
}

DisassemblerTextView::~DisassemblerTextView()
{
    if(m_blinktimerid != -1)
    {
        this->killTimer(m_blinktimerid);
        m_blinktimerid = -1;
    }

    if(m_refreshtimerid != -1)
    {
        this->killTimer(m_refreshtimerid);
        m_refreshtimerid = -1;
    }
}

DisassemblerActions *DisassemblerTextView::disassemblerActions() const { return m_actions; }
std::string DisassemblerTextView::currentWord() const { return m_renderer ? m_renderer->getCurrentWord() : std::string(); }
bool DisassemblerTextView::canGoBack() const { return this->currentDocument()->cursor()->canGoBack(); }
bool DisassemblerTextView::canGoForward() const { return this->currentDocument()->cursor()->canGoForward(); }

size_t DisassemblerTextView::visibleLines() const
{
    QFontMetrics fm = this->fontMetrics();
    size_t vl = std::ceil(this->height() / fm.height());

    if((vl <= 1) && (this->currentDocument()->size() >= DOCUMENT_IDEAL_SIZE))
        return DOCUMENT_IDEAL_SIZE;

    return vl;
}

size_t DisassemblerTextView::firstVisibleLine() const { return this->verticalScrollBar()->value(); }
size_t DisassemblerTextView::lastVisibleLine() const { return this->firstVisibleLine() + this->visibleLines() - 1; }

void DisassemblerTextView::setDisassembler(const REDasm::DisassemblerPtr& disassembler)
{
    m_disassembler = disassembler;

    EVENT_CONNECT(this->currentDocument(), changed, this, std::bind(&DisassemblerTextView::onDocumentChanged, this, std::placeholders::_1));

    EVENT_CONNECT(this->currentDocument()->cursor(), positionChanged, this, [&]() {
        QMetaObject::invokeMethod(this, "moveToSelection", Qt::QueuedConnection);
    });

    this->adjustScrollBars();

    connect(this->verticalScrollBar(), &QScrollBar::valueChanged, this, [&](int) { this->renderListing(); });

    m_renderer = std::make_unique<ListingTextRenderer>(m_disassembler.get());

    if(m_actions)
    {
        disconnect(this, &DisassemblerTextView::customContextMenuRequested, this, nullptr);
        m_actions->deleteLater();
    }

    m_actions = new DisassemblerActions(m_renderer.get(), this);

    connect(this, &DisassemblerTextView::customContextMenuRequested, this, [&](const QPoint&) {
        m_actions->popup(QCursor::pos());
    });

    m_disassemblerpopup = new DisassemblerPopup(m_disassembler, this);

    if(!m_disassembler->busy())
        this->currentDocument()->cursor()->positionChanged();
}

void DisassemblerTextView::copy()
{
    if(!m_actions)
        return;

    m_actions->copy();
}

void DisassemblerTextView::renderListing(const QRect &r)
{
    if(!m_disassembler || (m_disassembler->busy() && (m_refreshtimerid != -1)))
        return;

    if(r.isNull())
        this->viewport()->update();
    else
        this->viewport()->update(r);

    m_refreshtimerid = this->startTimer(m_refreshrate);
}

void DisassemblerTextView::blinkCursor()
{
    if(!m_disassembler || !this->isVisible())
        return;

    if(m_disassembler->busy())
    {
        this->currentDocument()->cursor()->toggle();
        return;
    }

    auto lock = REDasm::s_lock_safe_ptr(this->currentDocument());

    if(!this->hasFocus())
        lock->cursor()->disable();
    else
        lock->cursor()->toggle();

    this->renderLine(lock->cursor()->currentLine());
}

void DisassemblerTextView::scrollContentsBy(int dx, int dy)
{
    if(dx)
    {
        QWidget* viewport = this->viewport();
        viewport->move(viewport->x() + dx, viewport->y());
        return;
    }

    QAbstractScrollArea::scrollContentsBy(dx, dy);
}

void DisassemblerTextView::paintEvent(QPaintEvent *e)
{
    Q_UNUSED(e)

    if(!m_disassembler || !m_renderer)
        return;

    QFontMetrics fm = this->fontMetrics();
    const QRect& r = e->rect();

    size_t firstvisible = this->firstVisibleLine();
    size_t first = firstvisible + (r.top() / fm.height());
    size_t last = firstvisible + (r.bottom() / fm.height());

    QPainter painter(this->viewport());
    painter.setFont(this->font());
    m_renderer->setFirstVisibleLine(firstvisible);
    this->paintLines(&painter, first, last);
}

void DisassemblerTextView::resizeEvent(QResizeEvent *e)
{
    QAbstractScrollArea::resizeEvent(e);
    this->adjustScrollBars();
}

void DisassemblerTextView::mousePressEvent(QMouseEvent *e)
{
    REDasm::ListingCursor* cur = this->currentDocument()->cursor();

    if((e->button() == Qt::LeftButton) || (!cur->hasSelection() && (e->button() == Qt::RightButton)))
    {
        e->accept();
        m_renderer->moveTo(e->pos());
    }
    else if(e->button() == Qt::BackButton)
        this->currentDocument()->cursor()->goBack();
    else if(e->button() == Qt::ForwardButton)
        this->currentDocument()->cursor()->goForward();

    QAbstractScrollArea::mousePressEvent(e);
}

void DisassemblerTextView::mouseMoveEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::LeftButton)
    {
        e->accept();
        this->currentDocument()->cursor()->disable();

        QPoint pos = e->pos();
        pos.rx() = std::max(0, pos.x());
        pos.ry() = std::max(0, pos.y());
        m_renderer->select(pos);
    }
    else
        QAbstractScrollArea::mouseMoveEvent(e);
}

void DisassemblerTextView::mouseReleaseEvent(QMouseEvent *e)
{
    if(e->button() == Qt::LeftButton)
        e->accept();

    QAbstractScrollArea::mouseReleaseEvent(e);
}

void DisassemblerTextView::mouseDoubleClickEvent(QMouseEvent *e)
{
    if(e->button() == Qt::LeftButton)
    {
        if(!m_actions->followUnderCursor())
            m_renderer->selectWordAt(e->pos());

        e->accept();
        return;
    }

    QAbstractScrollArea::mouseReleaseEvent(e);
}

void DisassemblerTextView::wheelEvent(QWheelEvent *e)
{
    if(e->orientation() == Qt::Vertical)
    {
        int value = this->verticalScrollBar()->value();

        if(e->delta() < 0) // Scroll Down
            this->verticalScrollBar()->setValue(value + DOCUMENT_WHEEL_LINES);
        else if(e->delta() > 0) // Scroll Up
            this->verticalScrollBar()->setValue(value - DOCUMENT_WHEEL_LINES);

        return;
    }

    QAbstractScrollArea::wheelEvent(e);
}

void DisassemblerTextView::keyPressEvent(QKeyEvent *e)
{
    auto lock = REDasm::s_lock_safe_ptr(this->currentDocument());
    REDasm::ListingCursor* cur = lock->cursor();
    cur->enable();

    if(e->matches(QKeySequence::MoveToNextChar) || e->matches(QKeySequence::SelectNextChar))
    {
        size_t len = m_renderer->getLastColumn(cur->currentLine());

        if(len == cur->currentColumn())
            return;

        if(e->matches(QKeySequence::MoveToNextChar))
            cur->moveTo(cur->currentLine(), std::min(len, cur->currentColumn() + 1));
        else
            cur->select(cur->currentLine(), std::min(len, cur->currentColumn() + 1));
    }
    else if(e->matches(QKeySequence::MoveToPreviousChar) || e->matches(QKeySequence::SelectPreviousChar))
    {
        if(!cur->currentColumn())
            return;

        if(e->matches(QKeySequence::MoveToPreviousChar))
            cur->moveTo(cur->currentLine(), std::max(size_t(0), cur->currentColumn() - 1));
        else
            cur->select(cur->currentLine(), std::max(size_t(0), cur->currentColumn() - 1));
    }
    else if(e->matches(QKeySequence::MoveToNextLine) || e->matches(QKeySequence::SelectNextLine))
    {
        if(lock->lastLine()  == cur->currentLine())
            return;

        size_t nextline = cur->currentLine() + 1;

        if(e->matches(QKeySequence::MoveToNextLine))
            cur->moveTo(nextline, std::min(cur->currentColumn(), m_renderer->getLastColumn(nextline)));
        else
            cur->select(nextline, std::min(cur->currentColumn(), m_renderer->getLastColumn(nextline)));
    }
    else if(e->matches(QKeySequence::MoveToPreviousLine) || e->matches(QKeySequence::SelectPreviousLine))
    {
        if(!cur->currentLine())
            return;

        size_t prevline = cur->currentLine() - 1;

        if(e->matches(QKeySequence::MoveToPreviousLine))
            cur->moveTo(prevline, std::min(cur->currentColumn(), m_renderer->getLastColumn(prevline)));
        else
            cur->select(prevline, std::min(cur->currentColumn(), m_renderer->getLastColumn(prevline)));
    }
    else if(e->matches(QKeySequence::MoveToNextPage) || e->matches(QKeySequence::SelectNextPage))
    {
        if(lock->lastLine()  == cur->currentLine())
            return;

        size_t pageline = std::min(lock->lastLine(), this->firstVisibleLine() + this->visibleLines());

        if(e->matches(QKeySequence::MoveToNextPage))
            cur->moveTo(pageline, std::min(cur->currentColumn(), m_renderer->getLastColumn(pageline)));
        else
            cur->select(pageline, std::min(cur->currentColumn(), m_renderer->getLastColumn(pageline)));
    }
    else if(e->matches(QKeySequence::MoveToPreviousPage) || e->matches(QKeySequence::SelectPreviousPage))
    {
        if(!cur->currentLine())
            return;

        size_t pageline = 0;

        if(this->firstVisibleLine() > this->visibleLines())
            pageline = std::max(size_t(0), this->firstVisibleLine() - this->visibleLines());

        if(e->matches(QKeySequence::MoveToPreviousPage))
            cur->moveTo(pageline, std::min(cur->currentColumn(), m_renderer->getLastColumn(pageline)));
        else
            cur->select(pageline, std::min(cur->currentColumn(), m_renderer->getLastColumn(pageline)));
    }
    else if(e->matches(QKeySequence::MoveToStartOfDocument) || e->matches(QKeySequence::SelectStartOfDocument))
    {
        if(!cur->currentLine())
            return;

        if(e->matches(QKeySequence::MoveToStartOfDocument))
            cur->moveTo(0, 0);
        else
            cur->select(0, 0);
    }
    else if(e->matches(QKeySequence::MoveToEndOfDocument) || e->matches(QKeySequence::SelectEndOfDocument))
    {
        if(lock->lastLine() == cur->currentLine())
            return;

        if(e->matches(QKeySequence::MoveToEndOfDocument))
            cur->moveTo(lock->lastLine(), m_renderer->getLastColumn(lock->lastLine()));
        else
            cur->select(lock->lastLine(), m_renderer->getLastColumn(lock->lastLine()));
    }
    else if(e->matches(QKeySequence::MoveToStartOfLine) || e->matches(QKeySequence::SelectStartOfLine))
    {
        if(e->matches(QKeySequence::MoveToStartOfLine))
            cur->moveTo(cur->currentLine(), 0);
        else
            cur->select(cur->currentLine(), 0);
    }
    else if(e->matches(QKeySequence::MoveToEndOfLine) || e->matches(QKeySequence::SelectEndOfLine))
    {
        if(e->matches(QKeySequence::MoveToEndOfLine))
            cur->moveTo(cur->currentLine(), m_renderer->getLastColumn(cur->currentLine()));
        else
            cur->select(cur->currentLine(), m_renderer->getLastColumn(cur->currentLine()));
    }
    else if(e->key() == Qt::Key_Space)
        emit switchView();
    else
        QAbstractScrollArea::keyPressEvent(e);
}

void DisassemblerTextView::timerEvent(QTimerEvent *e)
{
    if(e->timerId() == m_refreshtimerid)
    {
        this->killTimer(m_refreshtimerid);
        m_refreshtimerid = -1;
        this->renderListing();
    }
    if(e->timerId() == m_blinktimerid)
        this->blinkCursor();

    QAbstractScrollArea::timerEvent(e);
}

bool DisassemblerTextView::event(QEvent *e)
{
    if(m_disassembler && !m_disassembler->busy() && (e->type() == QEvent::ToolTip))
    {
        QHelpEvent* helpevent = static_cast<QHelpEvent*>(e);
        this->showPopup(helpevent->pos());
        return true;
    }

    return QAbstractScrollArea::event(e);
}

void DisassemblerTextView::paintLines(QPainter *painter, u64 first, u64 last)
{
    u64 count = (last - first) + 1;
    m_renderer->render(first, count, painter);
}

void DisassemblerTextView::onDocumentChanged(const REDasm::ListingDocumentChanged *ldc)
{
    m_disassembler->document()->cursor()->clearSelection();
    this->adjustScrollBars();

    if(ldc->action != REDasm::ListingDocumentChanged::Changed) // Insertion or Deletion
    {
        if(ldc->index > this->lastVisibleLine()) // Don't care of bottom Insertion/Deletion
            return;

        //QMetaObject::invokeMethod(this, "renderListing", Qt::QueuedConnection);
    }
    else
        QMetaObject::invokeMethod(this, "renderLine", Qt::QueuedConnection, Q_ARG(u64, ldc->index));
}

REDasm::ListingDocument &DisassemblerTextView::currentDocument() { return m_disassembler->document(); }
const REDasm::ListingDocument &DisassemblerTextView::currentDocument() const { return m_disassembler->document();  }

const REDasm::Symbol* DisassemblerTextView::symbolUnderCursor()
{
    auto lock = REDasm::s_lock_safe_ptr(this->currentDocument());
    return lock->symbol(m_renderer->getCurrentWord());
}

bool DisassemblerTextView::isLineVisible(size_t line) const
{
    if(line < this->firstVisibleLine())
        return false;

    if(line > this->lastVisibleLine())
        return false;

    return true;
}

bool DisassemblerTextView::isColumnVisible(size_t column, size_t *xpos)
{
    QScrollBar* hscrollbar = this->horizontalScrollBar();
    u64 lastxpos = hscrollbar->value() + this->width();

#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    u64 adv = this->fontMetrics().horizontalAdvance(" ");
#else
    u64 adv = this->fontMetrics().width(" ");
#endif

    *xpos = adv * column;

    if(*xpos > lastxpos)
    {
        *xpos -= this->width();
        return false;
    }
    if(*xpos < this->width())
    {
        *xpos = 0;
        return false;
    }
    if(*xpos < static_cast<size_t>(hscrollbar->value()))
    {
        *xpos = hscrollbar->value() - *xpos;
        return false;
    }

    return true;
}

QRect DisassemblerTextView::lineRect(size_t line)
{
    if(!this->isLineVisible(line))
        return QRect();

    QRect vprect = this->viewport()->rect();
    QFontMetrics fm = this->fontMetrics();
    u64 offset = line - this->firstVisibleLine();
    return QRect(vprect.x(), offset * fm.height(), vprect.width(), fm.height());
}

void DisassemblerTextView::renderLine(size_t line)
{
    if(!this->isLineVisible(line))
        return;

    this->paintLines(line, line);
}

void DisassemblerTextView::paintLines(size_t first, size_t last)
{
    first = std::max(first, this->firstVisibleLine());
    last = std::min(last, this->lastVisibleLine());

    QRect firstrect = this->lineRect(first);
    QRect lastrect = this->lineRect(last);

    this->renderListing(QRect(firstrect.topLeft(), lastrect.bottomRight()));
}

void DisassemblerTextView::adjustScrollBars()
{
    if(!m_disassembler)
        return;

    QScrollBar* vscrollbar = this->verticalScrollBar();
    auto lock = REDasm::s_lock_safe_ptr(this->currentDocument());

    if(static_cast<int>(lock->size()) <= this->visibleLines())
        vscrollbar->setMaximum(static_cast<int>(lock->size()));
    else
        vscrollbar->setMaximum(static_cast<int>(lock->size() - this->visibleLines() + 1));

    this->ensureColumnVisible();
}

void DisassemblerTextView::moveToSelection()
{
    auto lock = REDasm::s_lock_safe_ptr(this->currentDocument());
    REDasm::ListingCursor* cur = lock->cursor();

    if(!this->isLineVisible(cur->currentLine())) // Center on selection
    {
        QScrollBar* vscrollbar = this->verticalScrollBar();
        vscrollbar->setValue(std::max(static_cast<s64>(0), static_cast<s64>(cur->currentLine() - this->visibleLines() / 2)));
    }
    else
        this->renderListing();

    this->ensureColumnVisible();
    REDasm::ListingItem* item = lock->itemAt(cur->currentLine());

    if(item)
        emit addressChanged(item->address);
}

void DisassemblerTextView::ensureColumnVisible()
{
    if(!m_disassembler)
        return;

    auto lock = REDasm::s_lock_safe_ptr(this->currentDocument());
    REDasm::ListingCursor* cur = lock->cursor();
    size_t xpos = 0;

    if(this->isColumnVisible(cur->currentColumn(), &xpos))
        return;

    QScrollBar* hscrollbar = this->horizontalScrollBar();
    hscrollbar->setValue(xpos);
}

void DisassemblerTextView::showPopup(const QPoint& pos)
{
    std::string word = m_renderer->getWordFromPos(pos);

    if(!word.empty())
    {
        REDasm::ListingCursor::Position cp = m_renderer->hitTest(pos);
        m_disassemblerpopup->popup(word, cp.first);
        return;
    }

    m_disassemblerpopup->hide();
}
