#include "disassemblertextview.h"
#include "../../dialogs/referencesdialog.h"
#include "../../dialogs/callgraphdialog.h"
#include "../../themeprovider.h"
#include <QFontDatabase>
#include <QJsonDocument>
#include <QInputDialog>
#include <QHeaderView>
#include <QMessageBox>
#include <QMouseEvent>
#include <QTextBlock>
#include <QScrollBar>
#include <QAction>
#include <QtMath>
#include <QMenu>

DisassemblerTextView::DisassemblerTextView(QWidget *parent): QPlainTextEdit(parent), _issymboladdressvalid(false), _emitmode(DisassemblerTextView::Normal), _disdocument(NULL), _disassembler(NULL), _currentaddress(INT64_MAX), _symboladdress(0)
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setPointSize(12);
    font.setStyleHint(QFont::TypeWriter);

    this->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    this->setContextMenuPolicy(Qt::CustomContextMenu);
    this->setWordWrapMode(QTextOption::NoWrap);
    this->setFrameStyle(QFrame::NoFrame);
    this->setCenterOnScroll(true);
    this->setFont(font);
    this->createContextMenu();

    viewport()->setCursor(Qt::ArrowCursor);

    this->_highlighter = new DisassemblerHighlighter(this->document());

    connect(this, &DisassemblerTextView::customContextMenuRequested, [this](const QPoint&) {
        this->_contextmenu->exec(QCursor::pos());
    });
}

DisassemblerTextView::~DisassemblerTextView()
{
}

bool DisassemblerTextView::canGoBack() const
{
    return !this->_backstack.isEmpty();
}

bool DisassemblerTextView::canGoForward() const
{
    return !this->_forwardstack.isEmpty();
}

address_t DisassemblerTextView::currentAddress() const
{
    return this->_currentaddress;
}

address_t DisassemblerTextView::symbolAddress() const
{
    return this->_symboladdress;
}

void DisassemblerTextView::setEmitMode(u32 emitmode)
{
    this->_emitmode = emitmode;
}

void DisassemblerTextView::setDisassembler(REDasm::Disassembler *disassembler)
{
    if(this->_disdocument)
        delete this->_disdocument;

    this->_disassembler = disassembler;
    this->_disdocument = new DisassemblerTextDocument(disassembler, "light", this->document(), this);
    this->_highlighter->setHighlightColor(ThemeProvider::highlightColor());
    this->_highlighter->setSeekColor(ThemeProvider::seekColor());
    this->_highlighter->setDottedColor(ThemeProvider::dottedColor());

    REDasm::SymbolPtr symbol = disassembler->symbolTable()->entryPoint();

    if(!symbol)
    {
        disassembler->symbolTable()->iterate(REDasm::SymbolTypes::FunctionMask, [&symbol](const REDasm::SymbolPtr& s) -> bool {
            symbol = s;
            return false;
        });
    }

    if(symbol)
        this->display(symbol->address);
}

void DisassemblerTextView::goTo(address_t address)
{
    if(this->_currentaddress != address)
    {
        this->_backstack.push(this->_currentaddress);
        emit canGoBackChanged();
    }

    this->display(address);
}

void DisassemblerTextView::display(address_t address)
{
    if(this->_emitmode == EmitMode::VMIL)
    {
        this->clear();
        this->_disdocument->generateVMIL(address, this->textCursor());
        return;
    }

    if(!this->_disdocument || (this->_currentaddress == address))
        return;

    this->_disdocument->generate(address, this->textCursor());

    QTextDocument* document = this->document();
    QTextCursor cursor = this->textCursor();
    bool searchforward = address > this->_currentaddress;

    for(QTextBlock b = !this->_currentaddress ? document->begin(): cursor.block(); b.isValid(); b = searchforward ? b.next() : b.previous())
    {
        QTextBlockFormat blockformat = b.blockFormat();

        if(!blockformat.hasProperty(DisassemblerTextDocument::IsInstructionBlock) && !blockformat.hasProperty(DisassemblerTextDocument::IsSymbolBlock))
            continue;

        bool ok = false;
        address_t blockaddress = blockformat.property(DisassemblerTextDocument::Address).toULongLong(&ok);

        if(!ok || (blockaddress != address))
            continue;

        this->setTextCursor(QTextCursor(b));
        this->ensureCursorVisible();
        this->updateAddress();
        this->highlightWords();
        break;
    }
}

void DisassemblerTextView::checkLabel(address_t address)
{
    u64 c = this->_disassembler->getReferencesCount(address);

    if(!c)
        return;

    if(c == 1)
    {
        REDasm::ReferenceVector refs = this->_disassembler->getReferences(address);
        this->goTo(refs.front());
        return;
    }

    this->showReferences(address);
}

void DisassemblerTextView::goTo(const REDasm::SymbolPtr &symbol)
{
    this->goTo(symbol->address);
}

void DisassemblerTextView::goBack()
{
    if(this->_backstack.isEmpty())
        return;

    address_t address = this->_backstack.pop();
    this->_forwardstack.push(this->_currentaddress);

    emit canGoBackChanged();
    emit canGoForwardChanged();
    this->display(address);
}

void DisassemblerTextView::goForward()
{
    if(this->_forwardstack.isEmpty())
        return;

    address_t address = this->_forwardstack.pop();
    this->_backstack.push(this->_currentaddress);

    emit canGoBackChanged();
    emit canGoForwardChanged();
    this->display(address);
}

void DisassemblerTextView::resizeEvent(QResizeEvent *e)
{
    QPlainTextEdit::resizeEvent(e);
    this->highlightWords();
}

void DisassemblerTextView::wheelEvent(QWheelEvent *e)
{
    QPlainTextEdit::wheelEvent(e);
    this->highlightWords();
}

void DisassemblerTextView::mouseReleaseEvent(QMouseEvent *e)
{
    this->updateAddress();
    this->highlightWords();

    address_t address = 0;

    if(!this->getCursorAnchor(address))
    {
        this->_issymboladdressvalid = false;
        emit symbolDeselected();
    }
    else
        this->updateSymbolAddress(address);

    QPlainTextEdit::mouseReleaseEvent(e);
}

void DisassemblerTextView::mouseDoubleClickEvent(QMouseEvent *e)
{
    QPlainTextEdit::mouseDoubleClickEvent(e);

    int action = 0;
    address_t address = 0;

    if(!(action = this->getCursorAnchor(address)))
        return;

    if(action == DisassemblerTextDocument::LabelAction)
        this->checkLabel(address);
    else
        this->goTo(address);
}

void DisassemblerTextView::keyPressEvent(QKeyEvent *e)
{
    QPlainTextEdit::keyPressEvent(e);

    if(e->key() == Qt::Key_X)
    {
        int action = 0;
        address_t address = 0;

        if(!(action = this->getCursorAnchor(address)))
            return;

        this->showReferences(address);
    }
    else if(e->key() == Qt::Key_N)
        this->rename(this->_symboladdress);
}

void DisassemblerTextView::createContextMenu()
{
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
}

void DisassemblerTextView::adjustContextMenu()
{
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
}

void DisassemblerTextView::highlightWords()
{
    if(!this->_disdocument || !this->_currentaddress)
        return;

    QTextCursor cursor = this->textCursor();
    cursor.select(QTextCursor::WordUnderCursor);

    QString currentaddress = HEX_ADDRESS(this->_currentaddress);

    for(QTextBlock b = this->firstVisibleBlock(); b.isValid() && b.isVisible(); b = b.next())
        this->_highlighter->highlight(cursor.selectedText(), currentaddress, b);
}

void DisassemblerTextView::updateAddress()
{
    QTextCursor cursor = this->textCursor();
    QTextBlockFormat blockformat = cursor.blockFormat();

    if(!blockformat.hasProperty(DisassemblerTextDocument::Address))
        return;

    bool ok = false;
    address_t address = blockformat.property(DisassemblerTextDocument::Address).toULongLong(&ok);

    if(!ok || address == this->_currentaddress)
        return;

    this->_currentaddress = address;
    emit addressChanged(this->_currentaddress);
}

void DisassemblerTextView::updateSymbolAddress(address_t address)
{
    this->_issymboladdressvalid = true;
    this->_symboladdress = address;
    emit symbolAddressChanged();
}

void DisassemblerTextView::showReferences(address_t address)
{
    REDasm::SymbolPtr symbol = this->_disassembler->symbolTable()->symbol(address);

    if(!symbol)
        return;

    if(!this->_disassembler->getReferencesCount(address))
    {
        QMessageBox::information(this, "No References", "There are no references to " + S_TO_QS(symbol->name));
        return;
    }

    ReferencesDialog dlgreferences(this->_disassembler, this->_currentaddress, symbol, this);
    connect(&dlgreferences, &ReferencesDialog::jumpTo, [this](address_t address) { this->goTo(address); });
    dlgreferences.exec();
}

void DisassemblerTextView::showCallGraph(address_t address)
{
    CallGraphDialog dlgcallgraph(address, this->_disassembler, this);
    dlgcallgraph.exec();
}

int DisassemblerTextView::getCursorAnchor(address_t& address)
{
    QTextCursor cursor = this->textCursor();
    QTextCharFormat charformat = cursor.charFormat();

    if(!charformat.isAnchor())
        return DisassemblerTextDocument::NoAction;

    QJsonObject data = DisassemblerTextDocument::decode(charformat.anchorHref());
    int action = data["action"].toInt();

    if(action != DisassemblerTextDocument::NoAction)
        address = data["address"].toVariant().toULongLong();

    return action;
}

void DisassemblerTextView::rename(address_t address)
{
    if(!this->_issymboladdressvalid)
        return;

    REDasm::SymbolPtr symbol = this->_disassembler->symbolTable()->symbol(address);

    if(!symbol)
        return;

    REDasm::SymbolTable* symboltable = this->_disassembler->symbolTable();
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

    if(s.simplified().isEmpty() || !symboltable->update(symbol, newsym))
        return;

    this->_disdocument->update(address);
    emit symbolRenamed(symbol);
}
