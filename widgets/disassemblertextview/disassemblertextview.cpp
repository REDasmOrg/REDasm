#include "disassemblertextview.h"
#include "../../dialogs/referencesdialog.h"
#include "../../dialogs/callgraphdialog.h"
#include <cmath>
#include <QTimer>
#include <QPainter>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QJsonDocument>
#include <QInputDialog>
#include <QMessageBox>
#include <QMouseEvent>
#include <QScrollBar>
#include <QAction>
#include <QMenu>

#define CURSOR_BLINK_INTERVAL 500 // 500ms

DisassemblerTextView::DisassemblerTextView(QWidget *parent): QAbstractScrollArea(parent), m_emitmode(DisassemblerTextView::Normal), m_renderer(NULL), m_disassembler(NULL)
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setStyleHint(QFont::TypeWriter);
    font.setPointSize(12);

    this->setFont(font);
    this->setCursor(Qt::ArrowCursor);
    this->setContextMenuPolicy(Qt::CustomContextMenu);
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
void DisassemblerTextView::setEmitMode(u32 emitmode) { m_emitmode = emitmode; }

void DisassemblerTextView::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    disassembler->finished += std::bind(&DisassemblerTextView::onDisassemblerFinished, this);

    REDasm::ListingDocument* doc = disassembler->document();
    doc->changed += std::bind(&DisassemblerTextView::onDocumentChanged, this, std::placeholders::_1);

    this->verticalScrollBar()->setRange(0, doc->size());
    connect(this->verticalScrollBar(), &QScrollBar::valueChanged, [&](int) { this->update(); });

    m_disassembler = disassembler;
    m_renderer = new ListingTextRenderer(this->font(), disassembler);
    m_blinktimer->start();
    this->update();
}

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

    doc->cursor()->select(idx);
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

void DisassemblerTextView::paintEvent(QPaintEvent *e)
{
    Q_UNUSED(e)

    if(!m_renderer)
        return;

    QScrollBar* vscrollbar = this->verticalScrollBar();
    QPainter painter(this->viewport());
    painter.setFont(this->font());

    m_renderer->render(vscrollbar->value(), this->visibleLines(), &painter);
}

void DisassemblerTextView::mousePressEvent(QMouseEvent *e)
{
    if((e->button() == Qt::LeftButton) || (e->button() == Qt::RightButton))
    {
        REDasm::ListingCursor* cur = m_disassembler->document()->cursor();
        REDasm::ListingCursor::Position cp = m_renderer->hitTest(e->pos(), this->verticalScrollBar());
        cur->select(cp.first, cp.second);
    }

    QAbstractScrollArea::mousePressEvent(e);
}

void DisassemblerTextView::keyPressEvent(QKeyEvent *e)
{
    if(e->key() == Qt::Key_X)
    {
        this->showReferences();
    }
    //else if(e->key() == Qt::Key_N)
        //this->rename(m_symboladdress);
}

void DisassemblerTextView::onDisassemblerFinished()
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::ListingCursor* cur = doc->cursor();

    cur->selectionChanged += std::bind(&DisassemblerTextView::moveToSelection, this);
    cur->backChanged += [=]() { emit canGoBackChanged(); };
    cur->forwardChanged += [=]() { emit canGoForwardChanged(); };

    this->moveToSelection();
}

void DisassemblerTextView::onDocumentChanged(const REDasm::ListingDocumentChanged *ldc)
{
    QScrollBar* vscrollbar = this->verticalScrollBar();
    vscrollbar->setMaximum(m_disassembler->document()->size());

    if((ldc->index < vscrollbar->value()) || (ldc->index > vscrollbar->value() + this->visibleLines()))
        return;

    this->update();
}

REDasm::SymbolPtr DisassemblerTextView::symbolUnderCursor()
{
    const std::string& word = m_disassembler->document()->cursor()->wordUnderCursor();

    if(word.empty())
        return NULL;

    return m_disassembler->document()->symbol(word);
}

int DisassemblerTextView::visibleLines() const
{
    QFontMetrics fm = this->fontMetrics();
    return std::ceil(this->height() / fm.height());
}

int DisassemblerTextView::lastVisibleLine() const
{
    QScrollBar* vscrollbar = this->verticalScrollBar();
    return vscrollbar->value() + this->visibleLines();
}

bool DisassemblerTextView::isLineVisible(int line) const
{
    QScrollBar* vscrollbar = this->verticalScrollBar();
    return (line >= vscrollbar->value()) && (line < this->lastVisibleLine());
}

void DisassemblerTextView::moveToSelection()
{
    QScrollBar* vscrollbar = this->verticalScrollBar();
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::ListingCursor* cur = doc->cursor();

    if(this->isLineVisible(cur->currentLine()))
    {
        this->update();
        m_renderer->findWordUnderCursor();
    }
    else
        vscrollbar->setValue(cur->currentLine());

    REDasm::ListingItem* item = doc->itemAt(cur->currentLine());

    if(item)
        emit addressChanged(item->address);
}

void DisassemblerTextView::createContextMenu()
{
    m_contextmenu = new QMenu(this);
    m_actrename = m_contextmenu->addAction("Rename", [=]() { /* this->rename(this->_symboladdress); */ } );

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
    m_actcopy = m_contextmenu->addAction("Copy");
    m_actselectall = m_contextmenu->addAction("Select All");

    connect(m_contextmenu, &QMenu::aboutToShow, this, &DisassemblerTextView::adjustContextMenu);
}

void DisassemblerTextView::adjustContextMenu()
{
    m_actback->setVisible(this->canGoBack());
    m_actforward->setVisible(this->canGoForward());

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

void DisassemblerTextView::followUnderCursor()
{
    REDasm::SymbolPtr symbol = this->symbolUnderCursor();

    if(!symbol)
        return;

    this->goTo(symbol->address);
}

void DisassemblerTextView::rename(address_t address)
{
    REDasm::SymbolPtr symbol = m_disassembler->document()->symbol(address);

    if(!symbol)
        return;

    REDasm::SymbolTable* symboltable = m_disassembler->document()->symbols(); // FIXME: !!!
    QString sym = S_TO_QS(symbol->name), s = QInputDialog::getText(this, QString("Rename %1").arg(sym), "Symbol name:", QLineEdit::Normal, sym);

    if(s.isEmpty())
        return;

    REDasm::SymbolPtr checksymbol = symboltable->symbol(s.toStdString());

    if(checksymbol)
    {
        QMessageBox::warning(this, "Rename failed", "Duplicate symbol name");
        this->rename(address);
        return;
    }

    std::string newsym = s.simplified().replace(" ", "_").toStdString();

    /*
    if(s.simplified().isEmpty() || !symboltable->update(symbol, newsym))
        return;

    m_dasmdocument->update(address);
    emit symbolRenamed(symbol);
    */
}
