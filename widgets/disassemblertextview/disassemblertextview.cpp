#include "disassemblertextview.h"
#include "../../dialogs/referencesdialog.h"
#include "../../dialogs/callgraphdialog.h"
#include <cmath>
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

DisassemblerTextView::DisassemblerTextView(QWidget *parent): QAbstractScrollArea(parent), m_issymboladdressvalid(false), m_emitmode(DisassemblerTextView::Normal), m_renderer(NULL), m_disassembler(NULL), m_currentaddress(INT64_MAX), m_symboladdress(0)
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setStyleHint(QFont::TypeWriter);
    font.setPointSize(12);

    this->setFont(font);
    this->setCursor(Qt::ArrowCursor);
    this->verticalScrollBar()->setValue(0);
    this->verticalScrollBar()->setSingleStep(1);
    this->verticalScrollBar()->setPageStep(1);

    connect(this, &DisassemblerTextView::customContextMenuRequested, [this](const QPoint&) {
        m_contextmenu->exec(QCursor::pos());
    });
}

DisassemblerTextView::~DisassemblerTextView()
{
    if(!m_renderer)
        return;

    delete m_renderer;
    m_renderer = NULL;
}

bool DisassemblerTextView::canGoBack() const { return !m_backstack.isEmpty(); }
bool DisassemblerTextView::canGoForward() const { return !m_forwardstack.isEmpty(); }
address_t DisassemblerTextView::currentAddress() const { return m_currentaddress; }
address_t DisassemblerTextView::symbolAddress() const { return m_symboladdress; }
void DisassemblerTextView::setEmitMode(u32 emitmode) { m_emitmode = emitmode; }

void DisassemblerTextView::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    REDasm::ListingDocument* doc = disassembler->document();
    REDasm::ListingCursor* cur = doc->cursor();

    doc->changed += std::bind(&DisassemblerTextView::onDocumentChanged, this, std::placeholders::_1);
    cur->selectionChanged += std::bind(&DisassemblerTextView::onSelectionChanged, this);

    this->verticalScrollBar()->setRange(0, doc->size());
    connect(this->verticalScrollBar(), &QScrollBar::valueChanged, [this](int) { this->update(); });

    m_disassembler = disassembler;
    m_renderer = new ListingTextRenderer(this->font(), disassembler);
    this->update();
}

void DisassemblerTextView::goTo(address_t address)
{
    if(m_currentaddress != address)
    {
        m_backstack.push(m_currentaddress);
        emit canGoBackChanged();
    }

    //this->display(address);
}

void DisassemblerTextView::goTo(const REDasm::SymbolPtr &symbol) { this->goTo(symbol->address); }

void DisassemblerTextView::goBack()
{
    if(m_backstack.isEmpty())
        return;

    address_t address = m_backstack.pop();
    m_forwardstack.push(m_currentaddress);

    emit canGoBackChanged();
    emit canGoForwardChanged();
}

void DisassemblerTextView::goForward()
{
    if(m_forwardstack.isEmpty())
        return;

    address_t address = m_forwardstack.pop();
    m_backstack.push(m_currentaddress);

    emit canGoBackChanged();
    emit canGoForwardChanged();
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

void DisassemblerTextView::keyPressEvent(QKeyEvent *e)
{
    if(e->key() == Qt::Key_X)
    {
        int action = 0;
        address_t address = 0;

        if(!(action = this->getCursorAnchor(address)))
            return;

        this->showReferences(address);
    }
    else if(e->key() == Qt::Key_N)
        this->rename(m_symboladdress);
}

void DisassemblerTextView::onDocumentChanged(const REDasm::ListingDocumentChanged *ldc)
{
    QScrollBar* vscrollbar = this->verticalScrollBar();
    vscrollbar->setMaximum(m_disassembler->document()->size());

    if((ldc->index < vscrollbar->value()) || (ldc->index > vscrollbar->value() + this->visibleLines()))
        return;

    this->update();
}

void DisassemblerTextView::onSelectionChanged()
{

}

int DisassemblerTextView::visibleLines() const
{
    QFontMetrics fm = this->fontMetrics();
    return std::ceil(this->height() / fm.height());
}

void DisassemblerTextView::createContextMenu()
{
    /*
    this->_contextmenu = new QMenu(this);

    this->_actrename = this->_contextmenu->addAction("Rename", [this]() { this->rename(this->_symboladdress);} );

    this->_actcreatestring = this->_contextmenu->addAction("Create String", [this]() {
        if(!this->_disassembler->dataToString(this->_symboladdress))
            return;

        this->_disdocument->update(this->_symboladdress);
        emit invalidateSymbols();
    });

    this->_contextmenu->addSeparator();
    this->_actxrefs = this->_contextmenu->addAction("Cross References", [this]() { this->showReferences(this->_symboladdress); });
    this->_actfollow = this->_contextmenu->addAction("Follow", [this]() { this->goTo(this->_symboladdress); });
    this->_actgoto = this->_contextmenu->addAction("Goto...", this, &DisassemblerTextView::gotoRequested);
    this->_actcallgraph = this->_contextmenu->addAction("Call Graph", [this]() { this->showCallGraph(this->_symboladdress); });
    this->_acthexdump = this->_contextmenu->addAction("Hex Dump", [this]() { emit hexDumpRequested(this->_symboladdress); });
    this->_contextmenu->addSeparator();
    this->_actback = this->_contextmenu->addAction("Back", this, &DisassemblerTextView::goBack);
    this->_actforward = this->_contextmenu->addAction("Forward", this, &DisassemblerTextView::goForward);
    this->_contextmenu->addSeparator();
    this->_actcopy = this->_contextmenu->addAction("Copy", this, &DisassemblerTextView::copy);
    this->_actselectall = this->_contextmenu->addAction("Select All", this, &DisassemblerTextView::selectAll);

    connect(this->_contextmenu, &QMenu::aboutToShow, this, &DisassemblerTextView::adjustContextMenu);
    */
}

void DisassemblerTextView::adjustContextMenu()
{
    /*
    this->_actback->setVisible(this->canGoBack());
    this->_actforward->setVisible(this->canGoForward());

    QTextCursor cursor = this->textCursor();
    QTextCharFormat charformat = cursor.charFormat();
    QString encdata = charformat.isAnchor() ? charformat.anchorHref() : QString();

    if(!this->_issymboladdressvalid || encdata.isEmpty())
    {
        this->_actrename->setVisible(false);
        this->_actcreatestring->setVisible(false);
        this->_actxrefs->setVisible(false);
        this->_actfollow->setVisible(false);
        this->_actcallgraph->setVisible(false);
        this->_acthexdump->setVisible(false);
        return;
    }

    QTextBlockFormat blockformat = cursor.blockFormat();
    QJsonObject data = this->_disdocument->decode(encdata);

    if(blockformat.hasProperty(DisassemblerTextDocument::IsLabelBlock))
        this->updateSymbolAddress(blockformat.property(DisassemblerTextDocument::Address).toULongLong());
    else
        this->updateSymbolAddress(data["address"].toVariant().toULongLong());

    REDasm::Segment* segment = this->_disassembler->format()->segment(this->_symboladdress);
    REDasm::SymbolPtr symbol = this->_disassembler->symbolTable()->symbol(this->_symboladdress);

    this->_actrename->setVisible(symbol != NULL);
    this->_actcallgraph->setVisible(symbol && symbol->isFunction());

    if((segment && segment->is(REDasm::SegmentTypes::Data)) && (symbol && !symbol->isFunction() && symbol->is(REDasm::SymbolTypes::Data)))
    {
        u64 c = this->_disassembler->locationIsString(this->_symboladdress);

        if(c > 1)
            this->_actcreatestring->setVisible(c > 1);
    }
    else
        this->_actcreatestring->setVisible(false);

    this->_acthexdump->setVisible(segment && !segment->is(REDasm::SegmentTypes::Bss));
    this->_actxrefs->setVisible(symbol != NULL);
    this->_actback->setVisible(this->canGoBack());
    this->_actforward->setVisible(this->canGoForward());
    this->_actfollow->setVisible(symbol && (symbol->is(REDasm::SymbolTypes::Code)));
    this->_acthexdump->setVisible(segment && !segment->is(REDasm::SegmentTypes::Bss));
    */
}

void DisassemblerTextView::highlightWords()
{
    if(!m_currentaddress)
        return;

    //QTextCursor cursor = this->textCursor();
    //cursor.select(QTextCursor::WordUnderCursor);

    //QString currentaddress = HEX_ADDRESS(this->_currentaddress);

    //for(QTextBlock b = this->firstVisibleBlock(); b.isValid() && b.isVisible(); b = b.next())
        //this->_highlighter->highlight(cursor.selectedText(), currentaddress, b);
}

void DisassemblerTextView::updateAddress()
{
    //QTextCursor cursor = this->textCursor();
    //QTextBlockFormat blockformat = cursor.blockFormat();

    //if(!blockformat.hasProperty(DisassemblerTextDocument::Address))
        //return;

    //bool ok = false;
    //address_t address = blockformat.property(DisassemblerTextDocument::Address).toULongLong(&ok);

    //if(!ok || address == this->_currentaddress)
        //return;

    //this->_currentaddress = address;
    //emit addressChanged(this->_currentaddress);
}

void DisassemblerTextView::updateSymbolAddress(address_t address)
{
    m_issymboladdressvalid = true;
    m_symboladdress = address;
    emit symbolAddressChanged();
}

void DisassemblerTextView::showReferences(address_t address)
{
    REDasm::SymbolPtr symbol = m_disassembler->document()->symbol(address);

    if(!symbol)
        return;

    if(!m_disassembler->getReferencesCount(address))
    {
        QMessageBox::information(this, "No References", "There are no references to " + S_TO_QS(symbol->name));
        return;
    }

    ReferencesDialog dlgreferences(m_disassembler, m_currentaddress, symbol, this);
    connect(&dlgreferences, &ReferencesDialog::jumpTo, [this](address_t address) { this->goTo(address); });
    dlgreferences.exec();
}

void DisassemblerTextView::showCallGraph(address_t address)
{
    //CallGraphDialog dlgcallgraph(address, m_disassembler, this);
    //dlgcallgraph.exec();
}

int DisassemblerTextView::getCursorAnchor(address_t& address)
{
    /*
    QTextCursor cursor = this->textCursor();
    QTextCharFormat charformat = cursor.charFormat();

    if(!charformat.isAnchor())
        return DisassemblerTextDocument::NoAction;

    QJsonObject data = DisassemblerTextDocument::decode(charformat.anchorHref());
    int action = data["action"].toInt();

    if(action != DisassemblerTextDocument::NoAction)
        address = data["address"].toVariant().toULongLong();

    return action;
    */

    return 0;
}

void DisassemblerTextView::rename(address_t address)
{
    if(!m_issymboladdressvalid)
        return;

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
