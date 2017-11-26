#include "disassemblertextview.h"
#include "../../dialogs/referencesdialog.h"
#include <QFontDatabase>
#include <QInputDialog>
#include <QHeaderView>
#include <QMouseEvent>
#include <QTextBlock>
#include <QScrollBar>
#include <QAction>
#include <QtMath>
#include <QMenu>
#include <QFile>

DisassemblerTextView::DisassemblerTextView(QWidget *parent) : QTextBrowser(parent), _disdocument(NULL), _disassembler(NULL), _currentaddress(0), _menuaddress(0)
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setPointSize(12);
    font.setStyleHint(QFont::TypeWriter);

    this->setFont(font);
    this->setFrameStyle(QFrame::NoFrame);
    this->setWordWrapMode(QTextOption::NoWrap);
    this->setOpenLinks(false);
    this->setContextMenuPolicy(Qt::CustomContextMenu);
    this->createContextMenu();

    connect(this, &DisassemblerTextView::customContextMenuRequested, [this](const QPoint& pt) {
        this->highlightLineAt(pt);
        this->_contextmenu->exec(QCursor::pos());
    });

    connect(this, &DisassemblerTextView::anchorClicked, [this](const QUrl& encdata) { this->executeAnchor(encdata.toString()); });
}

DisassemblerTextView::~DisassemblerTextView()
{
    if(this->_disdocument)
        delete this->_disdocument;
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

void DisassemblerTextView::setDisassembler(REDasm::Disassembler *disassembler)
{
    if(this->_disdocument)
        delete this->_disdocument;

    this->_disassembler = disassembler;

    this->_disdocument = new DisassemblerDocument(disassembler);
    this->_disdocument->setTheme("light");
    this->disassemble();

    REDasm::Symbol* symbol = disassembler->symbols()->entryPoint();

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
    if(!this->_disdocument)
        return;

    int line = this->_disdocument->lineFromAddress(address);
    this->focusLine(line);
}

void DisassemblerTextView::goTo(REDasm::Symbol *symbol)
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

void DisassemblerTextView::mouseReleaseEvent(QMouseEvent *ev)
{
    QTextCursor cursor = this->textCursor();

    if(!cursor.hasSelection())
        this->highlightLineAt(ev->pos());

    QTextBrowser::mouseReleaseEvent(ev);
}

void DisassemblerTextView::executeAnchor(const QString &encdata)
{
    QJsonObject data = DisassemblerDocument::decode(encdata);
    int action = data["action"].toInt();

    if(action == DisassemblerDocument::NoAction)
        return;

    address_t address = data["address"].toVariant().toULongLong();

    if(action == DisassemblerDocument::XRefAction)
        this->showReferences(address);
    else if(action == DisassemblerDocument::GotoAction)
        this->goTo(address);
}

int DisassemblerTextView::lineFromPos(const QPoint &pos) const
{
    qreal h = this->fontMetrics().height(), offset = this->verticalScrollBar()->value() / h;
    return qFloor(offset + (pos.y() / h));
}

int DisassemblerTextView::firstVisibleLine() const
{
    return this->lineFromPos(QPoint(0, 0));
}

int DisassemblerTextView::lastVisibleLine() const
{
    return this->lineFromPos(QPoint(0, this->height()));
}

int DisassemblerTextView::visibleLines() const
{
    return this->height() / this->fontMetrics().height();
}

void DisassemblerTextView::centerSelection()
{
    int fl = this->firstVisibleLine(), hl = this->visibleLines() / 2;

    if(this->textCursor().blockNumber() <= fl)
        this->verticalScrollBar()->setValue((fl - hl) * this->fontMetrics().height());
    else
        this->verticalScrollBar()->setValue((fl + hl) * this->fontMetrics().height());
}

void DisassemblerTextView::createContextMenu()
{
    this->_contextmenu = new QMenu(this);

    this->_actrename = this->_contextmenu->addAction("Rename", [this]() { this->rename(this->_menuaddress);} );

    this->_actcreatefunction = this->_contextmenu->addAction("Create Function", [this]() {
        this->_disassembler->disassembleFunction(this->_menuaddress);

        this->updateListing();
        this->display(this->_currentaddress);
        emit invalidateSymbols();
    });

    this->_actcreatestring = this->_contextmenu->addAction("Create String", [this]() {
        if(!this->_disassembler->dataToString(this->_menuaddress))
            return;

        this->updateListing();
        this->display(this->_currentaddress);
        emit invalidateSymbols();
    });

    this->_contextmenu->addSeparator();
    this->_actxrefs = this->_contextmenu->addAction("Cross References", [this]() { this->showReferences(this->_menuaddress); });
    this->_actfollow = this->_contextmenu->addAction("Follow", [this]() { this->goTo(this->_menuaddress); });
    this->_actgoto = this->_contextmenu->addAction("Goto...", this, &DisassemblerTextView::gotoRequested);
    this->_acthexdump = this->_contextmenu->addAction("Hex Dump", [this]() { emit hexDumpRequested(this->_menuaddress); });
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
    QPoint pt = this->mapFromGlobal(QCursor::pos());
    QString encdata = this->anchorAt(pt);

    if(encdata.isEmpty())
    {
        this->_actrename->setVisible(false);
        this->_actcreatefunction->setVisible(false);
        this->_actxrefs->setVisible(false);
        this->_actback->setVisible(this->canGoBack());
        this->_actforward->setVisible(this->canGoForward());
        this->_actfollow->setVisible(false);
        this->_acthexdump->setVisible(false);
        return;
    }

    QJsonObject data = this->_disdocument->decode(encdata);
    this->_menuaddress = data["address"].toVariant().toULongLong();
    REDasm::Segment* segment = this->_disassembler->format()->segment(this->_menuaddress);
    REDasm::Symbol* symbol = this->_disassembler->symbols()->symbol(this->_menuaddress);

    this->_actrename->setVisible(symbol != NULL);

    this->_actcreatefunction->setVisible(segment && segment->is(REDasm::SegmentTypes::Code) &&
                                         symbol && !symbol->isFunction() && !symbol->is(REDasm::SymbolTypes::String));

    if((segment && segment->is(REDasm::SegmentTypes::Data)) && (symbol && !symbol->isFunction() && symbol->is(REDasm::SymbolTypes::Data)))
    {
        u64 c = this->_disassembler->locationIsString(this->_menuaddress);

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

void DisassemblerTextView::disassemble()
{
    this->_disdocument->populate();
    this->setHtml(this->_disdocument->toString());
}

void DisassemblerTextView::updateListing()
{
    int oldvalue = this->verticalScrollBar()->value();
    this->disassemble();
    this->verticalScrollBar()->setValue(oldvalue);
}

void DisassemblerTextView::highlightLineAt(const QPoint &pos)
{
    int line = qMax(0, this->lineFromPos(pos));
    this->highlightLine(line);
}

void DisassemblerTextView::highlightLine(int line)
{
    if(!this->_disdocument)
        return;

    QTextDocument* document = this->document();
    QTextBlock block = document->findBlockByLineNumber(line);

    if(!block.isValid())
        return;

    QTextCursor cursor(block);
    cursor.select(QTextCursor::LineUnderCursor);

    QTextEdit::ExtraSelection selection;
    selection.format.setBackground(QColor(this->_disdocument->lineColor()));
    selection.format.setProperty(QTextFormat::FullWidthSelection, true);
    selection.cursor = cursor;
    selection.cursor.clearSelection();

    QList<QTextBrowser::ExtraSelection> extraselections;
    extraselections << selection;
    this->setExtraSelections(extraselections);

    QDomNodeList nodes = this->_disdocument->childNodes();
    QDomElement e = nodes.item(line).toElement();

    if(e.isNull() || !e.hasAttribute("address"))
        return;

    bool ok = false;
    this->_currentaddress = e.attribute("address").toULongLong(&ok, 16);

    if(ok)
        emit addressChanged(this->_currentaddress);
}

void DisassemblerTextView::focusLine(int line)
{
    if(line < 0)
        return;

    QTextDocument* document = this->document();
    QTextBlock block = document->findBlockByLineNumber(line);

    if(!block.isValid())
        return;

    QTextCursor cursor(block);
    cursor.movePosition(QTextCursor::StartOfBlock);

    this->setTextCursor(cursor);
    this->highlightLine(line);
    this->centerSelection();
}

void DisassemblerTextView::focusLineAt(address_t address)
{
    int line = this->_disdocument->lineFromAddress(address);
    this->focusLine(line);
}

void DisassemblerTextView::showReferences(address_t address)
{
    REDasm::Symbol* symbol = this->_disassembler->symbols()->symbol(address);

    if(!symbol)
        return;

    ReferencesDialog dlgreferences(this->_disassembler, this->_currentaddress, symbol, this);
    connect(&dlgreferences, &ReferencesDialog::jumpTo, [this](address_t address) { this->goTo(address); });
    dlgreferences.exec();
}

void DisassemblerTextView::rename(address_t address)
{
    REDasm::Symbol* symbol = this->_disassembler->symbols()->symbol(address);

    if(!symbol)
        return;

    REDasm::SymbolTable* symboltable = this->_disassembler->symbols();
    QString sym = S_TO_QS(symbol->name), s = QInputDialog::getText(this, QString("Rename %1").arg(sym), "Symbol name:", QLineEdit::Normal, sym);
    std::string newsym = s.simplified().replace(" ", "_").toStdString();

    if(s.simplified().isEmpty() || !symboltable->rename(symbol, newsym))
        return;

    this->updateListing();
    emit symbolRenamed(symbol);
}
