#include "disassemblertextview.h"
#include "../../dialogs/referencesdialog.h"
#include <QFontDatabase>
#include <QJsonDocument>
#include <QInputDialog>
#include <QHeaderView>
#include <QMouseEvent>
#include <QTextBlock>
#include <QScrollBar>
#include <QAction>
#include <QtMath>
#include <QMenu>
#include <QDebug>

#define THEME_VALUE(name) (this->_theme.contains(name) ? QColor(this->_theme[name].toString()) : QColor())

DisassemblerTextView::DisassemblerTextView(QWidget *parent): QPlainTextEdit(parent), _disdocument(NULL), _disassembler(NULL), _currentaddress(0), _menuaddress(0)
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
    this->_disdocument = new DisassemblerDocument(disassembler, "light", this->document(), this->textCursor(), this);
    this->_highlighter->setHighlightColor(this->_disdocument->highlightColor());
    this->_highlighter->setSeekColor(this->_disdocument->seekColor());

    REDasm::SymbolPtr symbol = disassembler->symbolTable()->entryPoint();

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
    if(!this->_disdocument || (this->_currentaddress == address))
        return;

    QTextDocument* document = this->document();
    QTextCursor cursor = this->textCursor();
    bool searchforward = address > this->_currentaddress;

    for(QTextBlock b = !this->_currentaddress ? document->begin(): cursor.block(); b.isValid(); b = searchforward ? b.next() : b.previous())
    {
        QTextBlockFormat blockformat = b.blockFormat();

        if(!blockformat.hasProperty(DisassemblerDocument::IsInstructionBlock))
            continue;

        bool ok = false;
        address_t blockaddress = blockformat.property(DisassemblerDocument::Address).toULongLong(&ok);

        if(!ok || (blockaddress != address))
            continue;

        this->setTextCursor(QTextCursor(b));
        this->ensureCursorVisible();
        this->updateAddress();
        this->highlightWords();
        break;
    }
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
    QPlainTextEdit::mouseReleaseEvent(e);
}

void DisassemblerTextView::mouseDoubleClickEvent(QMouseEvent *e)
{
    QPlainTextEdit::mouseDoubleClickEvent(e);

    int action = 0;
    address_t address = 0;

    if(!(action = this->getCursorAnchor(address)))
        return;

    if(action == DisassemblerDocument::XRefAction)
        this->showReferences(address);
    else if(action == DisassemblerDocument::GotoAction)
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
}

void DisassemblerTextView::createContextMenu()
{
    this->_contextmenu = new QMenu(this);

    this->_actrename = this->_contextmenu->addAction("Rename", [this]() { this->rename(this->_menuaddress);} );

    this->_actcreatefunction = this->_contextmenu->addAction("Create Function", [this]() {
        this->_disassembler->disassembleFunction(this->_menuaddress);

        this->display(this->_currentaddress);
        emit invalidateSymbols();
    });

    this->_actcreatestring = this->_contextmenu->addAction("Create String", [this]() {
        if(!this->_disassembler->dataToString(this->_menuaddress))
            return;

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
        this->_actcreatestring->setVisible(false);
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
    REDasm::SymbolPtr symbol = this->_disassembler->symbolTable()->symbol(this->_menuaddress);

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

    if(!blockformat.hasProperty(DisassemblerDocument::Address))
        return;

    bool ok = false;
    address_t address = blockformat.property(DisassemblerDocument::Address).toULongLong(&ok);

    if(!ok || address == this->_currentaddress)
        return;

    this->_currentaddress = address;
    emit addressChanged(this->_currentaddress);
}

void DisassemblerTextView::showReferences(address_t address)
{
    REDasm::SymbolPtr symbol = this->_disassembler->symbolTable()->symbol(address);

    if(!symbol)
        return;

    ReferencesDialog dlgreferences(this->_disassembler, this->_currentaddress, symbol, this);
    connect(&dlgreferences, &ReferencesDialog::jumpTo, [this](address_t address) { this->goTo(address); });
    dlgreferences.exec();
}

int DisassemblerTextView::getCursorAnchor(address_t& address)
{
    QTextCursor cursor = this->textCursor();
    QTextCharFormat charformat = cursor.charFormat();

    if(!charformat.isAnchor())
        return DisassemblerDocument::NoAction;

    QJsonObject data = DisassemblerDocument::decode(charformat.anchorHref());
    int action = data["action"].toInt();

    if(action != DisassemblerDocument::NoAction)
        address = data["address"].toVariant().toULongLong();

    return action;
}

void DisassemblerTextView::rename(address_t address)
{
    REDasm::SymbolPtr symbol = this->_disassembler->symbolTable()->symbol(address);

    if(!symbol)
        return;

    REDasm::SymbolTable* symboltable = this->_disassembler->symbolTable();
    QString sym = S_TO_QS(symbol->name), s = QInputDialog::getText(this, QString("Rename %1").arg(sym), "Symbol name:", QLineEdit::Normal, sym);
    std::string newsym = s.simplified().replace(" ", "_").toStdString();

    if(s.simplified().isEmpty() || !symboltable->update(symbol, newsym))
        return;

    emit symbolRenamed(symbol);
}
