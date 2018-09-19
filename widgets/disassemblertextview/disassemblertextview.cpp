#include "disassemblertextview.h"
#include "../../dialogs/referencesdialog.h"
#include "../../dialogs/callgraphdialog.h"
#include <cmath>
#include <QtGui>
#include <QtWidgets>

#define CURSOR_BLINK_INTERVAL 500 // 500ms

DisassemblerTextView::DisassemblerTextView(QWidget *parent): QAbstractScrollArea(parent), m_renderer(NULL), m_disassembler(NULL)
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setStyleHint(QFont::TypeWriter);

    this->setFont(font);
    this->setCursor(Qt::ArrowCursor);
    this->setContextMenuPolicy(Qt::CustomContextMenu);
    this->viewport()->setFocusPolicy(Qt::StrongFocus);
    this->verticalScrollBar()->setMinimum(0);
    this->verticalScrollBar()->setValue(0);
    this->verticalScrollBar()->setSingleStep(1);
    this->verticalScrollBar()->setPageStep(1);

    m_blinktimer = new QTimer(this);
    m_blinktimer->setInterval(CURSOR_BLINK_INTERVAL);

    connect(m_blinktimer, &QTimer::timeout, this, &DisassemblerTextView::blinkCursor);

    connect(this, &DisassemblerTextView::customContextMenuRequested, [&](const QPoint&) {
        m_contextmenu->exec(QCursor::pos());
    });

    this->createContextMenu();
}

DisassemblerTextView::~DisassemblerTextView()
{
    if(m_renderer)
    {
        delete m_renderer;
        m_renderer = NULL;
    }
}

bool DisassemblerTextView::canGoBack() const { return m_disassembler->document()->cursor()->canGoBack(); }
bool DisassemblerTextView::canGoForward() const { return m_disassembler->document()->cursor()->canGoForward(); }

void DisassemblerTextView::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    disassembler->finished += std::bind(&DisassemblerTextView::onDisassemblerFinished, this);

    REDasm::ListingDocument* doc = disassembler->document();
    doc->changed += std::bind(&DisassemblerTextView::onDocumentChanged, this, std::placeholders::_1);

    this->adjustScrollBars();
    connect(this->verticalScrollBar(), &QScrollBar::valueChanged, [&](int) { this->update(); });

    m_disassembler = disassembler;
    m_renderer = new ListingTextRenderer(this->font(), disassembler);
    m_blinktimer->start();
    this->update();
}

void DisassemblerTextView::copy() { qApp->clipboard()->setText(S_TO_QS(m_renderer->getSelectedText())); }

void DisassemblerTextView::goTo(address_t address)
{
    REDasm::ListingDocument* doc = m_disassembler->document();

    auto it = doc->instructionItem(address);

    if(it == doc->end())
        it = doc->symbolItem(address);

    if(it == doc->end())
        return;

    this->goTo((*it).get());
}

void DisassemblerTextView::goTo(REDasm::ListingItem *item)
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    int idx = doc->indexOf(item);

    if(idx == -1)
        return;

    doc->cursor()->moveTo(idx);
}

void DisassemblerTextView::goBack() { m_disassembler->document()->cursor()->goBack();  }
void DisassemblerTextView::goForward() { m_disassembler->document()->cursor()->goForward(); }

void DisassemblerTextView::blinkCursor()
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::ListingCursor* cur = doc->cursor();

    m_renderer->toggleCursor();

    if(!this->isLineVisible(cur->currentLine()))
        return;

    this->update();
}

bool DisassemblerTextView::viewportEvent(QEvent *e)
{
    if(e->type() == QEvent::WindowActivate)
    {
        m_renderer->enableCursor();
        m_blinktimer->start();
        return true;
    }
    else if(e->type() == QEvent::WindowDeactivate)
    {
        m_blinktimer->stop();
        m_renderer->disableCursor();
        return true;
    }

    return QAbstractScrollArea::viewportEvent(e);
}

void DisassemblerTextView::paintEvent(QPaintEvent *e)
{
    Q_UNUSED(e)

    if(!m_renderer)
        return;

    QPainter painter(this->viewport());
    painter.setFont(this->font());
    m_renderer->render(this->firstVisibleLine(), this->visibleLines(), &painter);
}

void DisassemblerTextView::resizeEvent(QResizeEvent *e)
{
    QAbstractScrollArea::resizeEvent(e);
    this->adjustScrollBars();
}

void DisassemblerTextView::mousePressEvent(QMouseEvent *e)
{
    REDasm::ListingCursor* cur = m_disassembler->document()->cursor();

    if((e->button() == Qt::LeftButton) || (!cur->hasSelection() && (e->button() == Qt::RightButton)))
    {
        e->accept();
        REDasm::ListingCursor::Position cp = m_renderer->hitTest(e->pos(), this->firstVisibleLine());
        cur->moveTo(cp.first, cp.second);
    }

    QAbstractScrollArea::mousePressEvent(e);
}

void DisassemblerTextView::mouseMoveEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::LeftButton)
    {
        e->accept();

        if(m_blinktimer->isActive())
        {
            m_blinktimer->stop();
            m_renderer->disableCursor();
        }

        REDasm::ListingCursor* cur = m_disassembler->document()->cursor();
        REDasm::ListingCursor::Position cp = m_renderer->hitTest(e->pos(), this->firstVisibleLine());
        cur->select(cp.first, cp.second);
        e->accept();
        return;
    }

    QAbstractScrollArea::mouseMoveEvent(e);
}

void DisassemblerTextView::mouseReleaseEvent(QMouseEvent *e)
{
    if(e->button() == Qt::LeftButton)
    {
        e->accept();

        if(!m_blinktimer->isActive())
            m_blinktimer->start();
    }

    QAbstractScrollArea::mouseReleaseEvent(e);
}

void DisassemblerTextView::mouseDoubleClickEvent(QMouseEvent *e)
{
    if(e->button() == Qt::LeftButton)
    {
        e->accept();

        if(this->followUnderCursor())
            return;

        REDasm::ListingCursor* cur = m_disassembler->document()->cursor();
        ListingTextRenderer::Range r = m_renderer->wordHitTest(e->pos(), this->firstVisibleLine());

        if(r.first == -1)
            return;

        cur->moveTo(cur->currentLine(), r.first);
        cur->select(cur->currentLine(), r.second);
        return;
    }

    QAbstractScrollArea::mouseReleaseEvent(e);
}

void DisassemblerTextView::keyPressEvent(QKeyEvent *e)
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::ListingCursor* cur = doc->cursor();

    m_blinktimer->stop();
    m_renderer->enableCursor();

    if(e->matches(QKeySequence::MoveToNextChar) || e->matches(QKeySequence::SelectNextChar))
    {
        int len = m_renderer->getLastColumn(cur->currentLine());

        if(e->matches(QKeySequence::MoveToNextChar))
            cur->moveTo(cur->currentLine(), std::min(len, cur->currentColumn() + 1));
        else
            cur->select(cur->currentLine(), std::min(len, cur->currentColumn() + 1));
    }
    else if(e->matches(QKeySequence::MoveToPreviousChar) || e->matches(QKeySequence::SelectPreviousChar))
    {
        if(e->matches(QKeySequence::MoveToNextChar))
            cur->moveTo(cur->currentLine(), std::max(0, cur->currentColumn() - 1));
        else
            cur->select(cur->currentLine(), std::max(0, cur->currentColumn() - 1));
    }
    else if(e->matches(QKeySequence::MoveToNextLine) || e->matches(QKeySequence::SelectNextLine))
    {
        if(doc->lastLine()  == cur->currentLine())
            return;

        int nextline = cur->currentLine() + 1;

        if(e->matches(QKeySequence::MoveToNextLine))
            cur->moveTo(nextline, std::min(cur->currentColumn(), m_renderer->getLastColumn(nextline)));
        else
            cur->select(nextline, std::min(cur->currentColumn(), m_renderer->getLastColumn(nextline)));
    }
    else if(e->matches(QKeySequence::MoveToPreviousLine) || e->matches(QKeySequence::SelectPreviousLine))
    {
        if(!cur->currentLine())
            return;

        int prevline = cur->currentLine() - 1;

        if(e->matches(QKeySequence::MoveToPreviousLine))
            cur->moveTo(prevline, std::min(cur->currentColumn(), m_renderer->getLastColumn(prevline)));
        else
            cur->select(prevline, std::min(cur->currentColumn(), m_renderer->getLastColumn(prevline)));
    }
    else if(e->matches(QKeySequence::MoveToNextPage) || e->matches(QKeySequence::SelectNextPage))
    {
        if(doc->lastLine()  == cur->currentLine())
            return;

        int pageline = std::min(doc->lastLine(), this->firstVisibleLine() + this->visibleLines());

        if(e->matches(QKeySequence::MoveToNextPage))
            cur->moveTo(pageline, std::min(cur->currentColumn(), m_renderer->getLastColumn(pageline)));
        else
            cur->select(pageline, std::min(cur->currentColumn(), m_renderer->getLastColumn(pageline)));
    }
    else if(e->matches(QKeySequence::MoveToPreviousPage) || e->matches(QKeySequence::SelectPreviousPage))
    {
        if(!cur->currentLine())
            return;

        int pageline = std::max(0, this->firstVisibleLine() - this->visibleLines());

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
        if(doc->lastLine() == cur->currentLine())
            return;

        if(e->matches(QKeySequence::MoveToEndOfDocument))
            cur->moveTo(doc->lastLine(), m_renderer->getLastColumn(doc->lastLine()));
        else
            cur->select(doc->lastLine(), m_renderer->getLastColumn(doc->lastLine()));
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
    else if(e->key() == Qt::Key_X)
        this->showReferences();
    else if(e->key() == Qt::Key_N)
        this->renameCurrentSymbol();

    m_blinktimer->start();
}

void DisassemblerTextView::onDisassemblerFinished()
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::ListingCursor* cur = doc->cursor();

    cur->positionChanged += std::bind(&DisassemblerTextView::moveToSelection, this);
    cur->backChanged += [=]() { emit canGoBackChanged(); };
    cur->forwardChanged += [=]() { emit canGoForwardChanged(); };

    this->moveToSelection();
    this->setFocus();
}

void DisassemblerTextView::onDocumentChanged(const REDasm::ListingDocumentChanged *ldc)
{
    QScrollBar* vscrollbar = this->verticalScrollBar();
    this->adjustScrollBars();

    if((ldc->index < vscrollbar->value()) || (ldc->index > vscrollbar->value() + this->visibleLines()))
        return;

    this->update();
}

REDasm::SymbolPtr DisassemblerTextView::symbolUnderCursor()
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::ListingCursor* cur = doc->cursor();

    if(!cur->hasWordUnderCursor())
        return NULL;

    return doc->symbol(cur->wordUnderCursor());
}

int DisassemblerTextView::visibleLines() const
{
    QFontMetrics fm = this->fontMetrics();
    return std::ceil(this->height() / fm.height());
}

int DisassemblerTextView::firstVisibleLine() const { return this->verticalScrollBar()->value(); }
int DisassemblerTextView::lastVisibleLine() const { return this->firstVisibleLine() + this->visibleLines() - 1; }

bool DisassemblerTextView::isLineVisible(int line) const
{
    if(line < this->firstVisibleLine())
        return false;

    if(line > this->lastVisibleLine())
        return false;

    return true;
}

void DisassemblerTextView::adjustScrollBars()
{
    if(!m_disassembler)
        return;

    QScrollBar* vscrollbar = this->verticalScrollBar();
    REDasm::ListingDocument* doc = m_disassembler->document();

    if(doc->size() <= static_cast<size_t>(this->visibleLines()))
        vscrollbar->setMaximum(doc->size());
    else
        vscrollbar->setMaximum(doc->size() - this->visibleLines());
}

void DisassemblerTextView::moveToSelection()
{
    QScrollBar* vscrollbar = this->verticalScrollBar();
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::ListingCursor* cur = doc->cursor();

    if(this->isLineVisible(cur->currentLine()))
    {
        this->update();
        m_renderer->updateWordUnderCursor();
    }
    else // Center on selection
        vscrollbar->setValue(std::max(0, cur->currentLine() - this->visibleLines() / 2));

    REDasm::ListingItem* item = doc->itemAt(cur->currentLine());

    if(item)
        emit addressChanged(item->address);
}

void DisassemblerTextView::createContextMenu()
{
    m_contextmenu = new QMenu(this);
    m_actrename = m_contextmenu->addAction("Rename", [=]() { this->renameCurrentSymbol(); } );

    m_contextmenu->addSeparator();
    m_actxrefs = m_contextmenu->addAction("Cross References", [&]() { this->showReferences(); });
    m_actfollow = m_contextmenu->addAction("Follow", [&]() { this->followUnderCursor(); });
    m_actgoto = m_contextmenu->addAction("Goto...", this, &DisassemblerTextView::gotoRequested);
    m_actcallgraph = m_contextmenu->addAction("Call Graph", [this]() { });
    m_acthexdump = m_contextmenu->addAction("Hex Dump", [this]() { });
    m_contextmenu->addSeparator();
    m_actback = m_contextmenu->addAction("Back", this, &DisassemblerTextView::goBack);
    m_actforward = m_contextmenu->addAction("Forward", this, &DisassemblerTextView::goForward);
    m_contextmenu->addSeparator();
    m_actcopy = m_contextmenu->addAction("Copy", this, &DisassemblerTextView::copy);

    connect(m_contextmenu, &QMenu::aboutToShow, this, &DisassemblerTextView::adjustContextMenu);
}

void DisassemblerTextView::adjustContextMenu()
{
    m_actback->setVisible(this->canGoBack());
    m_actforward->setVisible(this->canGoForward());
    m_actcopy->setVisible(m_disassembler->document()->cursor()->hasSelection());

    REDasm::SymbolPtr symbol = this->symbolUnderCursor();

    if(!symbol)
    {
        m_actrename->setVisible(false);
        m_actxrefs->setVisible(false);
        m_actfollow->setVisible(false);
        m_actcallgraph->setVisible(false);
        m_acthexdump->setVisible(false);
        return;
    }

    REDasm::Segment* segment = m_disassembler->document()->segment(symbol->address);

    m_actrename->setVisible(!symbol->isLocked());
    m_actcallgraph->setVisible(symbol->isFunction());
    m_actfollow->setVisible(symbol->is(REDasm::SymbolTypes::Code));
    m_acthexdump->setVisible(segment && !segment->is(REDasm::SegmentTypes::Bss));
    m_acthexdump->setVisible(segment && !segment->is(REDasm::SegmentTypes::Bss));
}

void DisassemblerTextView::showReferences()
{
    REDasm::SymbolPtr symbol = this->symbolUnderCursor();

    if(!symbol)
        return;

    if(!m_disassembler->getReferencesCount(symbol->address))
    {
        QMessageBox::information(this, "No References", "There are no references to " + S_TO_QS(symbol->name));
        return;
    }

    ReferencesDialog dlgreferences(m_disassembler, symbol, this);
    connect(&dlgreferences, &ReferencesDialog::jumpTo, [this](address_t address) { this->goTo(address); });
    dlgreferences.exec();
}

void DisassemblerTextView::showCallGraph(address_t address)
{
    //CallGraphDialog dlgcallgraph(address, m_disassembler, this);
    //dlgcallgraph.exec();
}

bool DisassemblerTextView::followUnderCursor()
{
    REDasm::SymbolPtr symbol = this->symbolUnderCursor();

    if(!symbol)
        return false;

    this->goTo(symbol->address);
    return true;
}

void DisassemblerTextView::renameCurrentSymbol()
{
    REDasm::SymbolPtr symbol = this->symbolUnderCursor();

    if(!symbol || symbol->isLocked())
        return;

    REDasm::ListingDocument* doc = m_disassembler->document();

    QString symbolname = S_TO_QS(symbol->name);
    QString res = QInputDialog::getText(this, QString("Rename %1").arg(symbolname), "Symbol name:", QLineEdit::Normal, symbolname);

    if(doc->symbol(res.toStdString()))
    {
        QMessageBox::warning(this, "Rename failed", "Duplicate symbol name");
        this->renameCurrentSymbol();
        return;
    }

    doc->rename(symbol->address, res.toStdString());
}
