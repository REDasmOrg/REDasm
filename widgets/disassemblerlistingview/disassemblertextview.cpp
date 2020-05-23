#include "disassemblertextview.h"
#include "../../hooks/disassemblerhooks.h"
#include <QScrollBar>
#include <QtGui>

#define DOCUMENT_IDEAL_SIZE   10
#define DOCUMENT_WHEEL_LINES  3

DisassemblerTextView::DisassemblerTextView(QWidget *parent): CursorScrollArea(parent)
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
}

DisassemblerTextView::~DisassemblerTextView() { std::for_each(m_events.begin(), m_events.end(), &RDEvent_Unsubscribe); }
RDDisassembler* DisassemblerTextView::disassembler() const { return m_disassembler; }
RDCursor* DisassemblerTextView::cursor() const { return m_renderer->cursor(); }
QWidget* DisassemblerTextView::widget() { return this; }
QString DisassemblerTextView::currentWord() const { return m_renderer ? m_renderer->currentWord() : QString(); }
const RDCursorPos* DisassemblerTextView::currentPosition() const { return m_renderer ? RDCursor_GetPosition(m_renderer->cursor()) : nullptr; }
const RDCursorPos* DisassemblerTextView::currentSelection() const { return m_renderer ? RDCursor_GetSelection(m_renderer->cursor()) : nullptr; }
bool DisassemblerTextView::canGoBack() const { return m_renderer ? RDCursor_CanGoBack(m_renderer->cursor()) : false; }
bool DisassemblerTextView::canGoForward() const { return m_renderer ? RDCursor_CanGoForward(m_renderer->cursor()) : false; }

bool DisassemblerTextView::getCurrentItem(RDDocumentItem* item) const
{
    if(!m_renderer) return false;
    return RDDocument_GetItemAt(m_document, RDCursor_CurrentLine(m_renderer->cursor()), item);
}

bool DisassemblerTextView::getSelectedSymbol(RDSymbol* symbol) const
{
    if(!m_renderer) return false;
    return m_renderer->selectedSymbol(symbol);
}

bool DisassemblerTextView::ownsCursor(const RDCursor* cursor) const { return m_renderer ? (m_renderer->cursor() == cursor) : false; }

size_t DisassemblerTextView::visibleLines() const
{
    QFontMetrics fm = this->fontMetrics();
    size_t vl = std::ceil(this->height() / fm.height());

    if((vl <= 1) && (RDDocument_ItemsCount(m_document) >= DOCUMENT_IDEAL_SIZE))
        return DOCUMENT_IDEAL_SIZE;

    return vl;
}

size_t DisassemblerTextView::firstVisibleLine() const { return this->verticalScrollBar()->value(); }
size_t DisassemblerTextView::lastVisibleLine() const { return this->firstVisibleLine() + this->visibleLines() - 1; }

void DisassemblerTextView::setDisassembler(RDDisassembler* disassembler)
{
    m_disassembler = disassembler;
    m_document = RDDisassembler_GetDocument(disassembler);

    m_renderer = std::make_unique<PainterRenderer>(disassembler);
    this->setBlinkCursor(m_renderer->cursor());

    m_events.insert(RDEvent_Subscribe(Event_BusyChanged, [](const RDEventArgs*, void* userdata) {
        if(RD_IsBusy()) return;
        DisassemblerTextView* thethis = reinterpret_cast<DisassemblerTextView*>(userdata);
        thethis->adjustScrollBars();

        RDDocument* doc = RDDisassembler_GetDocument(thethis->disassembler());
        RDLocation loc = RDDocument_EntryPoint(doc);

        if(loc.valid) thethis->gotoAddress(loc.address);
        else thethis->update();
    }, this));

    m_events.insert(RDEvent_Subscribe(Event_DocumentChanged, [](const RDEventArgs* e, void* userdata) {
        DisassemblerTextView* thethis = reinterpret_cast<DisassemblerTextView*>(userdata);
        thethis->onDocumentChanged(e);
    }, this));

    m_events.insert(RDEvent_Subscribe(Event_CursorPositionChanged, [](const RDEventArgs* e, void* userdata) {
        DisassemblerTextView* thethis = reinterpret_cast<DisassemblerTextView*>(userdata);
        if(e->sender != thethis->m_renderer->cursor()) return; // Ignore other cursors' events
        thethis->moveToSelection();
    }, this));

    this->adjustScrollBars();

    m_contextmenu = DisassemblerHooks::instance()->createActions(this);

    connect(this, &DisassemblerTextView::customContextMenuRequested, this, [&](const QPoint&) {
        if(RDDocument_ItemsCount(m_document)) m_contextmenu->popup(QCursor::pos());
    });

    m_disassemblerpopup = new DisassemblerPopup(m_disassembler, this);
}

bool DisassemblerTextView::gotoAddress(address_t address)
{
    if(!m_document) return false;

    RDDocumentItem item;
    bool ok = RDDocument_GetSymbolItem(m_document, address, &item);
    if(!ok) ok = RDDocument_GetInstructionItem(m_document, address, &item);
    if(!ok) return false;

    return this->gotoItem(item);
}

bool DisassemblerTextView::gotoItem(const RDDocumentItem& item)
{
    if(!m_document) return false;

    size_t idx = RDDocument_ItemIndex(m_document, &item);
    if(idx == RD_NPOS) return false;
    RDCursor_MoveTo(m_renderer->cursor(), idx, 0);
    return true;
}

void DisassemblerTextView::goBack() { if(m_renderer) RDCursor_GoBack(m_renderer->cursor()); }
void DisassemblerTextView::goForward() { if(m_renderer) RDCursor_GoForward(m_renderer->cursor()); }
bool DisassemblerTextView::hasSelection() const { return m_renderer ? RDCursor_HasSelection(m_renderer->cursor()) : false;  }
void DisassemblerTextView::copy() const { if(m_renderer) m_renderer->copy(); }

void DisassemblerTextView::scrollContentsBy(int dx, int dy)
{
    if(dx)
    {
        QWidget* viewport = this->viewport();
        viewport->move(viewport->x() + dx, viewport->y());
        return;
    }

    CursorScrollArea::scrollContentsBy(dx, dy);
}

void DisassemblerTextView::paintEvent(QPaintEvent *e)
{
    Q_UNUSED(e)
    if(!m_disassembler || !m_renderer) return;

    QFontMetrics fm = this->fontMetrics();
    QPainter painter(this->viewport());
    painter.setFont(this->font());
    m_renderer->render(&painter, this->firstVisibleLine(), this->lastVisibleLine());
}

void DisassemblerTextView::resizeEvent(QResizeEvent *e)
{
    CursorScrollArea::resizeEvent(e);
    this->adjustScrollBars();
}

void DisassemblerTextView::mousePressEvent(QMouseEvent *e)
{
    if((e->button() == Qt::LeftButton) || (!RDCursor_HasSelection(m_renderer->cursor()) && (e->button() == Qt::RightButton)))
    {
        e->accept();
        m_renderer->moveTo(this->viewportPoint(e->pos()));
    }

    CursorScrollArea::mousePressEvent(e);
}

void DisassemblerTextView::mouseMoveEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::LeftButton)
    {
        e->accept();
        RDCursor_Disable(m_renderer->cursor());

        QPoint pt = e->pos();
        pt.rx() = std::max(0, pt.x());
        pt.ry() = std::max(0, pt.y());

        m_renderer->select(this->viewportPoint(pt));
    }
    else
        CursorScrollArea::mouseMoveEvent(e);
}

void DisassemblerTextView::mouseDoubleClickEvent(QMouseEvent *e)
{
    if(e->button() == Qt::LeftButton)
    {
        if(!this->followUnderCursor())
            m_renderer->selectWordFromPoint(e->pos());

        e->accept();
        return;
    }

    CursorScrollArea::mouseReleaseEvent(e);
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

    CursorScrollArea::wheelEvent(e);
}

void DisassemblerTextView::keyPressEvent(QKeyEvent *e)
{
    const RDCursorPos* pos = RDCursor_GetPosition(m_renderer->cursor());
    size_t c = RDDocument_ItemsCount(m_document);

    if(e->matches(QKeySequence::MoveToNextChar) || e->matches(QKeySequence::SelectNextChar))
    {
        size_t len = RDRenderer_GetLastColumn(m_renderer->handle(), pos->line);
        if(len == pos->column) return;

        if(e->matches(QKeySequence::MoveToNextChar)) RDCursor_MoveTo(m_renderer->cursor(), pos->line, std::min(len, pos->column + 1));
        else RDCursor_Select(m_renderer->cursor(), pos->line, std::min(len, pos->column + 1));
    }
    else if(e->matches(QKeySequence::MoveToPreviousChar) || e->matches(QKeySequence::SelectPreviousChar))
    {
        if(!pos->column) return;

        if(e->matches(QKeySequence::MoveToPreviousChar)) RDCursor_MoveTo(m_renderer->cursor(), pos->line, std::max<size_t>(0, pos->column - 1));
        else RDCursor_Select(m_renderer->cursor(), pos->line, std::max<size_t>(0, pos->column - 1));
    }
    else if(e->matches(QKeySequence::MoveToNextLine) || e->matches(QKeySequence::SelectNextLine))
    {
        if((c - 1)  == pos->line) return;

        size_t nextline = pos->line + 1;
        if(e->matches(QKeySequence::MoveToNextLine)) RDCursor_MoveTo(m_renderer->cursor(), nextline, std::min(pos->column, RDRenderer_GetLastColumn(m_renderer->handle(), nextline)));
        else RDCursor_Select(m_renderer->cursor(), nextline, std::min(pos->column, RDRenderer_GetLastColumn(m_renderer->handle(), nextline)));
    }
    else if(e->matches(QKeySequence::MoveToPreviousLine) || e->matches(QKeySequence::SelectPreviousLine))
    {
        if(!pos->line) return;

        size_t prevline = pos->line - 1;
        if(e->matches(QKeySequence::MoveToPreviousLine)) RDCursor_MoveTo(m_renderer->cursor(), prevline, std::min(pos->column, RDRenderer_GetLastColumn(m_renderer->handle(), prevline)));
        else RDCursor_Select(m_renderer->cursor(), prevline, std::min(pos->column, RDRenderer_GetLastColumn(m_renderer->handle(), prevline)));
    }
    else if(e->matches(QKeySequence::MoveToNextPage) || e->matches(QKeySequence::SelectNextPage))
    {
        if((c - 1)  == pos->line) return;

        size_t pageline = std::min(c - 1, this->firstVisibleLine() + this->visibleLines());

        if(e->matches(QKeySequence::MoveToNextPage)) RDCursor_MoveTo(m_renderer->cursor(), pageline, std::min(pos->column, RDRenderer_GetLastColumn(m_renderer->handle(), pageline)));
        else RDCursor_Select(m_renderer->cursor(), pageline, std::min(pos->column, RDRenderer_GetLastColumn(m_renderer->handle(), pageline)));
    }
    else if(e->matches(QKeySequence::MoveToPreviousPage) || e->matches(QKeySequence::SelectPreviousPage))
    {
        if(!pos->line) return;

        size_t pageline = 0;
        if(this->firstVisibleLine() > this->visibleLines()) pageline = std::max<size_t>(0, this->firstVisibleLine() - this->visibleLines());

        if(e->matches(QKeySequence::MoveToPreviousPage)) RDCursor_MoveTo(m_renderer->cursor(), pageline, std::min(pos->column, RDRenderer_GetLastColumn(m_renderer->handle(), pageline)));
        else RDCursor_Select(m_renderer->cursor(), pageline, std::min(pos->column, RDRenderer_GetLastColumn(m_renderer->handle(), pageline)));
    }
    else if(e->matches(QKeySequence::MoveToStartOfDocument) || e->matches(QKeySequence::SelectStartOfDocument))
    {
        if(!pos->line) return;

        if(e->matches(QKeySequence::MoveToStartOfDocument)) RDCursor_MoveTo(m_renderer->cursor(), 0, 0);
        else RDCursor_Select(m_renderer->cursor(), 0, 0);
    }
    else if(e->matches(QKeySequence::MoveToEndOfDocument) || e->matches(QKeySequence::SelectEndOfDocument))
    {
        if((c - 1) == pos->line) return;

        if(e->matches(QKeySequence::MoveToEndOfDocument)) RDCursor_MoveTo(m_renderer->cursor(), c - 1, RDRenderer_GetLastColumn(m_renderer->handle(), c - 1));
        else RDCursor_Select(m_renderer->cursor(), c - 1, RDRenderer_GetLastColumn(m_renderer->handle(), c - 1));
    }
    else if(e->matches(QKeySequence::MoveToStartOfLine) || e->matches(QKeySequence::SelectStartOfLine))
    {
        if(e->matches(QKeySequence::MoveToStartOfLine)) RDCursor_MoveTo(m_renderer->cursor(), pos->line, 0);
        else RDCursor_Select(m_renderer->cursor(), pos->line, 0);
    }
    else if(e->matches(QKeySequence::MoveToEndOfLine) || e->matches(QKeySequence::SelectEndOfLine))
    {
        if(e->matches(QKeySequence::MoveToEndOfLine)) RDCursor_MoveTo(m_renderer->cursor(), pos->line, RDRenderer_GetLastColumn(m_renderer->handle(), pos->line));
        else RDCursor_Select(m_renderer->cursor(), pos->line, RDRenderer_GetLastColumn(m_renderer->handle(), pos->line));
    }
    else if(e->key() == Qt::Key_Space) emit switchView();
    else CursorScrollArea::keyPressEvent(e);
}

bool DisassemblerTextView::event(QEvent *e)
{
    if(m_disassembler && !RD_IsBusy() && (e->type() == QEvent::ToolTip))
    {
        QHelpEvent* helpevent = static_cast<QHelpEvent*>(e);
        this->showPopup(helpevent->pos());
        return true;
    }

    return CursorScrollArea::event(e);
}

void DisassemblerTextView::onDocumentChanged(const RDEventArgs *e)
{
    const auto* de = reinterpret_cast<const RDDocumentEventArgs*>(e);

    RDCursor_ClearSelection(m_renderer->cursor());
    this->adjustScrollBars();

    if(de->action != DocumentAction_ItemChanged) // Insertion or Deletion
    {
        if(de->index > this->lastVisibleLine()) // Don't care of out-of-screen Insertion/Deletion
            return;

        QMetaObject::invokeMethod(this->viewport(), "update", Qt::QueuedConnection);
    }
    else
        this->paintLine(de->index);
}

bool DisassemblerTextView::followUnderCursor()
{
    if(!m_renderer) return false;

    RDSymbol symbol;
    if(!m_renderer->selectedSymbol(&symbol)) return false;
    this->gotoAddress(symbol.address);
    return true;
}

bool DisassemblerTextView::isLineVisible(size_t line) const
{
    if(line < this->firstVisibleLine()) return false;
    if(line > this->lastVisibleLine()) return false;
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

QRect DisassemblerTextView::lineRect(size_t line) const
{
    if(!this->isLineVisible(line))
        return QRect();

    QRect vprect = this->viewport()->rect();
    QFontMetrics fm = this->fontMetrics();
    u64 offset = line - this->firstVisibleLine();
    return QRect(vprect.x(), offset * fm.height(), vprect.width(), fm.height());
}

QPointF DisassemblerTextView::viewportPoint(const QPointF& pt) const
{
    QPointF vpt;
    vpt.rx() = pt.x();
    vpt.ry() = pt.y() + (this->firstVisibleLine() * m_renderer->fontMetrics().height());
    return vpt;
}

void DisassemblerTextView::paintLine(size_t line)
{
    if(!this->isLineVisible(line)) return;
    this->paintLines(line, line);
}

void DisassemblerTextView::paintLines(size_t first, size_t last)
{
    first = std::max(first, this->firstVisibleLine());
    last = std::min(last, this->lastVisibleLine());

    QRect firstrect = this->lineRect(first);
    QRect lastrect = this->lineRect(last);

    this->viewport()->update(QRect(firstrect.topLeft(), lastrect.bottomRight()));
}

void DisassemblerTextView::adjustScrollBars()
{
    if(!m_disassembler) return;

    QScrollBar* vscrollbar = this->verticalScrollBar();
    size_t vl = this->visibleLines(), count = RDDocument_ItemsCount(m_document);

    if(count <= vl) vscrollbar->setMaximum(static_cast<int>(count));
    else vscrollbar->setMaximum(static_cast<int>(count - vl + 1));

    this->ensureColumnVisible();
}

void DisassemblerTextView::moveToSelection()
{
    if(!m_document) return;

    size_t c = RDDocument_ItemsCount(m_document);
    if(!c) return;

    size_t line = RDCursor_CurrentLine(m_renderer->cursor());

    if(!this->isLineVisible(line)) // Center on selection
    {
        QScrollBar* vscrollbar = this->verticalScrollBar();
        vscrollbar->setValue(static_cast<int>(std::max<size_t>(0, (line - this->visibleLines() / 2))));
    }
    else
        this->viewport()->update();

    this->ensureColumnVisible();
    if(line >= c) return;

    RDDocumentItem item;

    if(RDDocument_GetItemAt(m_document, line, &item))
        emit addressChanged(item.address);
}

void DisassemblerTextView::onCursorBlink() { this->paintLine(RDCursor_CurrentLine(m_renderer->cursor())); }

void DisassemblerTextView::ensureColumnVisible()
{
    if(!m_document) return;
    size_t xpos = 0;

    if(this->isColumnVisible(RDCursor_CurrentColumn(m_renderer->cursor()), &xpos))
        return;

    QScrollBar* hscrollbar = this->horizontalScrollBar();
    hscrollbar->setValue(static_cast<int>(xpos));
}

void DisassemblerTextView::showPopup(const QPoint& pt)
{
    if(!RDDocument_ItemsCount(m_document)) return;

    QString word = m_renderer->getWordFromPoint(pt, nullptr);

    if(!word.isEmpty())
    {
        RDCursorPos pos = m_renderer->hitTest(pt);
        m_disassemblerpopup->popup(word, pos.line);
        return;
    }

    m_disassemblerpopup->hide();
}
