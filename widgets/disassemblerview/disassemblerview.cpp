#include "disassemblerview.h"
#include "ui_disassemblerview.h"
#include "../../dialogs/dev/iteminformationdialog/iteminformationdialog.h"
#include "../../dialogs/referencesdialog/referencesdialog.h"
#include "../../themeprovider.h"
#include "../../redasmsettings.h"
#include <QHexView/document/buffer/qmemoryrefbuffer.h>
#include <QMessageBox>
#include <QPushButton>
#include <QDebug>

DisassemblerView::DisassemblerView(QLineEdit *lefilter, QWidget *parent) : QWidget(parent), ui(new Ui::DisassemblerView), m_disassembler(nullptr), m_hexdocument(nullptr), m_lefilter(lefilter)
{
    ui->setupUi(this);

    m_actions = new DisassemblerViewActions(this);
    m_docks = new DisassemblerViewDocks(this);

    m_listingview = new DisassemblerListingView(this);
    m_graphview = new DisassemblerGraphView(this);

    ui->hexView->setFont(REDasmSettings::font());
    ui->hexView->setFrameShape(QFrame::NoFrame);
    ui->hexView->setReadOnly(true);

    ui->stackedWidget->addWidget(m_listingview);
    ui->stackedWidget->addWidget(m_graphview);

    m_importsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItem::SymbolItem, ui->tvImports);
    static_cast<SymbolTableModel*>(m_importsmodel->sourceModel())->setSymbolType(REDasm::Symbol::T_Import);
    ui->tvImports->setModel(m_importsmodel);

    m_exportsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItem::AllItems, ui->tvExports);
    static_cast<SymbolTableModel*>(m_exportsmodel->sourceModel())->setSymbolType(REDasm::Symbol::T_Function);
    static_cast<SymbolTableModel*>(m_exportsmodel->sourceModel())->setSymbolFlags(REDasm::Symbol::F_Export);
    ui->tvExports->setModel(m_exportsmodel);

    m_stringsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItem::SymbolItem, ui->tvStrings);
    static_cast<SymbolTableModel*>(m_stringsmodel->sourceModel())->setSymbolType(REDasm::Symbol::T_String);
    ui->tvStrings->setModel(m_stringsmodel);

    m_segmentsmodel = ListingFilterModel::createFilter<SegmentsModel>(ui->tvSegments);
    ui->tvSegments->setModel(m_segmentsmodel);

    ui->tvSegments->verticalHeader()->setDefaultSectionSize(ui->tvSegments->verticalHeader()->minimumSectionSize());
    ui->tvImports->verticalHeader()->setDefaultSectionSize(ui->tvImports->verticalHeader()->minimumSectionSize());
    ui->tvExports->verticalHeader()->setDefaultSectionSize(ui->tvExports->verticalHeader()->minimumSectionSize());
    ui->tvStrings->verticalHeader()->setDefaultSectionSize(ui->tvStrings->verticalHeader()->minimumSectionSize());

    ui->tvSegments->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);
    ui->tvImports->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvImports->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvImports->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->tvExports->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvExports->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvExports->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->tvStrings->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvStrings->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvStrings->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);

    connect(ui->tabView, &QTabWidget::currentChanged, this, &DisassemblerView::checkHexEdit);
    connect(ui->tabView, &QTabWidget::currentChanged, this, &DisassemblerView::updateCurrentFilter);

    connect(ui->tabView, &QTabWidget::currentChanged, this, [=](int) {
        m_actions->setVisible(DisassemblerViewActions::BackAction, (ui->tabView->currentWidget() == ui->tabListing));
        m_actions->setVisible(DisassemblerViewActions::ForwardAction, (ui->tabView->currentWidget() == ui->tabListing));
        m_actions->setVisible(DisassemblerViewActions::GraphListingAction, (ui->tabView->currentWidget() == ui->tabListing));
    });

    connect(m_lefilter, &QLineEdit::textChanged, this, [&](const QString&) { this->filterSymbols(); });

    connect(m_listingview->textView(), &DisassemblerTextView::addressChanged, this, &DisassemblerView::displayAddress);
    connect(m_listingview->textView(), &DisassemblerTextView::addressChanged, this, &DisassemblerView::displayCurrentReferences);
    connect(m_listingview->textView(), &DisassemblerTextView::switchView, this, &DisassemblerView::switchGraphListing);
    connect(m_listingview->textView(), &DisassemblerTextView::addressChanged, m_docks, &DisassemblerViewDocks::updateCallGraph);

    connect(m_graphview, &DisassemblerGraphView::switchView, this, &DisassemblerView::switchGraphListing);
    connect(m_graphview, &DisassemblerGraphView::gotoDialogRequested, this, &DisassemblerView::showGoto);
    connect(m_graphview, &DisassemblerGraphView::hexDumpRequested, this, &DisassemblerView::selectToHexDump);
    connect(m_graphview, &DisassemblerGraphView::referencesRequested, this, &DisassemblerView::showReferences);
    connect(m_graphview, &DisassemblerGraphView::switchToHexDump, this, &DisassemblerView::switchToHexDump);
    connect(m_graphview, &DisassemblerGraphView::itemInformationRequested, this, &DisassemblerView::showCurrentItemInfo);
    connect(m_graphview, &DisassemblerGraphView::callGraphRequested, m_docks, &DisassemblerViewDocks::initializeCallGraph);

    connect(m_actions, &DisassemblerViewActions::backRequested, this, &DisassemblerView::goBack);
    connect(m_actions, &DisassemblerViewActions::forwardRequested, this, &DisassemblerView::goForward);
    connect(m_actions, &DisassemblerViewActions::gotoRequested, this, &DisassemblerView::showGoto);
    connect(m_actions, &DisassemblerViewActions::graphListingRequested, this, &DisassemblerView::switchGraphListing);

    connect(m_docks->referencesView(), &QTreeView::doubleClicked, this, &DisassemblerView::gotoXRef);
    connect(m_docks->callgraphView(), &QTreeView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(m_docks->callgraphView(), &QTreeView::doubleClicked, this, &DisassemblerView::goTo);
    connect(m_docks->callgraphView(), &QTreeView::customContextMenuRequested, this, &DisassemblerView::showMenu);
    connect(m_docks->functionsView(), &QTableView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(m_docks->functionsView(), &QTreeView::doubleClicked, this, &DisassemblerView::goTo);
    connect(m_docks->functionsView(), &QTreeView::customContextMenuRequested, this, &DisassemblerView::showMenu);

    connect(ui->tvSegments, &QTableView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(ui->tvSegments, &QTableView::doubleClicked, this, &DisassemblerView::goTo);
    connect(ui->tvExports,  &QTableView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(ui->tvExports,  &QTableView::doubleClicked, this, &DisassemblerView::goTo);
    connect(ui->tvExports,  &QTableView::customContextMenuRequested, this, &DisassemblerView::showMenu);
    connect(ui->tvImports,  &QTableView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(ui->tvImports,  &QTableView::doubleClicked, this, &DisassemblerView::goTo);
    connect(ui->tvImports,  &QTableView::customContextMenuRequested, this, &DisassemblerView::showMenu);
    connect(ui->tvStrings,  &QTableView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(ui->tvStrings,  &QTableView::doubleClicked, this, &DisassemblerView::goTo);
    connect(ui->tvStrings,  &QTableView::customContextMenuRequested, this, &DisassemblerView::showMenu);

    this->createActions();
}

DisassemblerView::~DisassemblerView()
{
    delete ui;
    if(m_disassembler) RD_Free(m_disassembler);
}

RDDisassembler *DisassemblerView::disassembler() { return m_disassembler; }

void DisassemblerView::bindDisassembler(RDDisassembler *disassembler)
{
    m_disassembler = disassembler; // Take ownership

    m_docks->setDisassembler(m_disassembler);
    m_importsmodel->setDisassembler(m_disassembler);
    m_exportsmodel->setDisassembler(m_disassembler);
    m_stringsmodel->setDisassembler(m_disassembler);
    m_segmentsmodel->setDisassembler(m_disassembler);

    RDBuffer* buffer = RDDisassembler_GetBuffer(disassembler);
    m_hexdocument = QHexDocument::fromMemory<QMemoryRefBuffer>(reinterpret_cast<char*>(RDBuffer_Data(buffer)), RDBuffer_Size(buffer), ui->hexView);
    ui->hexView->setDocument(m_hexdocument);

    m_listingview->setDisassembler(m_disassembler);
    //m_graphview->setDisassembler(m_disassembler);

    ui->stackedWidget->currentWidget()->setFocus();

    // r_evt::subscribe(REDasm::StandardEvents::Disassembler_BusyChanged, this, [&](const REDasm::EventArgs*) {
    //     QMetaObject::invokeMethod(this, "checkDisassemblerStatus", Qt::QueuedConnection);
    // });

    // r_evt::subscribe(REDasm::StandardEvents::Cursor_BackChanged, this, [&](const REDasm::EventArgs*) {
    //     m_actions->setEnabled(DisassemblerViewActions::BackAction, r_doc->cursor().canGoBack());
    // });

    // r_evt::subscribe(REDasm::StandardEvents::Cursor_ForwardChanged, this, [&](const REDasm::EventArgs*) {
    //     m_actions->setEnabled(DisassemblerViewActions::ForwardAction, r_doc->cursor().canGoForward());
    // });

    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::gotoDialogRequested, this, &DisassemblerView::showGoto);
    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::hexDumpRequested, this, &DisassemblerView::selectToHexDump);
    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::referencesRequested, this, &DisassemblerView::showReferences);
    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::switchToHexDump, this, &DisassemblerView::switchToHexDump);
    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::itemInformationRequested, this, &DisassemblerView::showCurrentItemInfo);
    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::callGraphRequested, m_docks, &DisassemblerViewDocks::initializeCallGraph);

    //m_actions->setEnabled(DisassemblerViewActions::BackAction, r_doc->cursor().canGoBack());
    //m_actions->setEnabled(DisassemblerViewActions::ForwardAction, r_doc->cursor().canGoForward());
}

void DisassemblerView::hideActions() { if(m_actions) m_actions->hideActions(); }

void DisassemblerView::checkDisassemblerStatus()
{
    m_actsetfilter->setEnabled(!RD_IsBusy());
    m_lefilter->setEnabled(!RD_IsBusy());

    //m_actions->setEnabled(DisassemblerViewActions::GotoAction, !m_disassembler->busy());
    //m_actions->setEnabled(DisassemblerViewActions::GraphListingAction, !m_disassembler->busy());
}

void DisassemblerView::modelIndexSelected(const QModelIndex &index)
{
    m_currentindex = index;
    m_actsetfilter->setVisible(index.isValid() && (index.model() != m_docks->callTreeModel()));
}

void DisassemblerView::checkHexEdit(int index)
{
    QWidget* w = ui->tabView->widget(index);
    if(!w || (w != ui->tabHexDump)) return;
    this->syncHexEdit();
}

void DisassemblerView::updateCurrentFilter(int index)
{
    QWidget* w = ui->tabView->widget(index);
    if(!w) return;

    if(w == ui->tabSegments) m_segmentsmodel->setFilterFixedString(m_lefilter->text());
    else if(w == ui->tabImports) m_importsmodel->setFilterFixedString(m_lefilter->text());
    else if(w == ui->tabExports) m_exportsmodel->setFilterFixedString(m_lefilter->text());
    else if(w == ui->tabStrings) m_stringsmodel->setFilterFixedString(m_lefilter->text());
}

void DisassemblerView::gotoXRef(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalId())
        return;

    ui->tabView->setCurrentWidget(ui->tabListing);
    //r_doc->goTo(static_cast<address_t>(index.internalId()));
}

void DisassemblerView::goTo(const QModelIndex &index)
{
    if(!index.isValid()) return;

    RDDocumentItem item;
    if(!this->itemFromIndex(index, &item)) return;

    //r_doc->goTo(item);

    if(!m_graphview->isCursorInGraph())
        ui->stackedWidget->setCurrentWidget(m_listingview);

    this->showListingOrGraph();
}

void DisassemblerView::showModelReferences()
{
    if(!m_currentindex.isValid()) return;

    RDDocumentItem item;
    if(!this->itemFromIndex(m_currentindex, &item)) return;

    RDDocument* doc = RDDisassembler_GetDocument(m_disassembler);
    RDSymbol symbol;

    if(m_currentindex.model() == m_docks->callTreeModel())
    {
        InstructionLock instruction(doc, item.address);
        if(!instruction) return;

        RDLocation loc = RDDisassembler_GetTarget(m_disassembler, instruction->address);
        if(!loc.valid || !RDDocument_GetSymbolByAddress(doc, loc.value, &symbol)) return;
    }
    else
    {
        if(!RDDocument_GetSymbolByAddress(doc, item.address, &symbol)) return;
    }

    this->showReferences(symbol.address);
}

void DisassemblerView::showCurrentItemInfo()
{
    // ItemInformationDialog dlgiteminfo(m_disassembler, this);
    // dlgiteminfo.exec();
}

void DisassemblerView::showReferences(address_t address)
{
    RDDocument* doc = RDDisassembler_GetDocument(m_disassembler);

    RDSymbol symbol;
    if(!RDDocument_GetSymbolByAddress(doc, address, &symbol)) return;

    if(!RDDisassembler_GetReferencesCount(m_disassembler, symbol.address))
    {
        QMessageBox::information(this, "No References", QString("There are no references to %1 ").arg(RDDocument_GetSymbolName(doc, symbol.address)));
        return;
    }

    ReferencesDialog dlgreferences(m_disassembler, &symbol, this->activeCursor(), this);

    // connect(&dlgreferences, &ReferencesDialog::jumpTo, this, [&](address_t address) {
    //     if(ui->stackedWidget->currentWidget() == m_graphview) {
    //         if(r_doc->itemInstruction(address).isValid()) {
    //             m_graphview->goTo(address);
    //             return;
    //         }

    //         this->switchGraphListing();
    //     }

    //     r_doc->goTo(address);
    //     ui->tabView->setCurrentWidget(ui->tabListing);
    // });

    dlgreferences.exec();
}

void DisassemblerView::displayAddress(address_t address)
{
    if(RD_IsBusy()) return;

    RDDocument* doc = RDDisassembler_GetDocument(m_disassembler);

    // const REDasm::Segment* segment = r_doc->segment(address);
    // const REDasm::Symbol* functionstart = r_doc->functionStartSymbol(address);
    // offset_location offset = r_ldr->offset(address);

    // QString segm = segment ? Convert::to_qstring(segment->name()) : "UNKNOWN",
    //         offs = segment && offset.valid ? Convert::to_qstring(REDasm::String::hex(offset.value, r_asm->bits())) : "UNKNOWN",
    //         addr = Convert::to_qstring(REDasm::String::hex(address, r_asm->bits()));

    // QString s = QString::fromWCharArray(L"<b>Address: </b>%1\u00A0\u00A0").arg(addr);
    // s += QString::fromWCharArray(L"<b>Offset: </b>%1\u00A0\u00A0").arg(offs);
    // s += QString::fromWCharArray(L"<b>Segment: </b>%1\u00A0\u00A0").arg(segm);

    // if(r_doc->currentItem().isValid() && functionstart)
    // {
    //     QString func = Convert::to_qstring(functionstart->name);

    //     if(address > functionstart->address)
    //         func += "+" + Convert::to_qstring(REDasm::String::hex(address - functionstart->address, 8));
    //     else if(address < functionstart->address)
    //         func += Convert::to_qstring(REDasm::String::hex<REDasm::signed_of<size_t>::type>(address - functionstart->address));

    //     s = QString::fromWCharArray(L"<b>Function: </b>%1\u00A0\u00A0").arg(func) + s;
    // }

    // r_ctx->status(qUtf8Printable(s));
}

void DisassemblerView::displayCurrentReferences()
{
    QString word = this->currentWord();

    if(!word.isEmpty())
    {
        RDDocument* doc = RDDisassembler_GetDocument(m_disassembler);
        RDSymbol symbol;

        if(RDDocument_GetSymbolByName(doc, qUtf8Printable(word), &symbol))
        {
            m_docks->referencesModel()->xref(symbol.address, this->activeCursor());
            return;
        }
    }

    RDDocumentItem item;
    if(this->getCurrentItem(&item)) m_docks->referencesModel()->xref(item.address, this->activeCursor());
    else m_docks->referencesModel()->clear();
}

void DisassemblerView::switchGraphListing()
{
    if(RD_IsBusy()) return;

    if(ui->stackedWidget->currentWidget() == m_listingview)
    {
        if(!m_graphview->renderGraph())
            return;

        m_actions->setIcon(DisassemblerViewActions::GraphListingAction, THEME_ICON("listing"));
        ui->stackedWidget->setCurrentWidget(m_graphview);
    }
    else
    {
        m_actions->setIcon(DisassemblerViewActions::GraphListingAction, THEME_ICON("graph"));
        ui->stackedWidget->setCurrentWidget(m_listingview);
    }
}

void DisassemblerView::switchToHexDump()
{
    this->syncHexEdit();
    ui->tabView->setCurrentWidget(ui->tabHexDump);
}

void DisassemblerView::toggleFilter()
{
    if(m_lefilter->isVisible()) this->clearFilter();
    else this->showFilter();
}

void DisassemblerView::filterSymbols()
{
    ListingFilterModel* filtermodel = this->getSelectedFilterModel();
    if(!filtermodel) return;
    filtermodel->setFilterFixedString(m_lefilter->text());
}

void DisassemblerView::showListingOrGraph()
{
    if(!ui->tabView->currentIndex()) return;
    ui->tabView->setCurrentIndex(0);
}

void DisassemblerView::showFilter()
{
    ListingFilterModel* filtermodel = this->getSelectedFilterModel();
    if(!filtermodel) return;

    m_lefilter->show();
    m_lefilter->setFocus();
}

void DisassemblerView::clearFilter()
{
    m_lefilter->clear();
    m_lefilter->hide();

    m_docks->functionsModel()->setFilterFixedString(QString());
    m_segmentsmodel->setFilterFixedString(QString());
    m_importsmodel->setFilterFixedString(QString());
    m_exportsmodel->setFilterFixedString(QString());
    m_stringsmodel->setFilterFixedString(QString());
}

void DisassemblerView::selectToHexDump(address_t address, u64 len)
{
    // offset_location offset = m_disassembler->loader()->offset(address);
    // if(!offset.valid) return;

    // ui->tabView->setCurrentWidget(ui->tabHexDump);

    // QHexCursor* cursor = ui->hexView->document()->cursor();
    // cursor->selectOffset(offset, len);
}

void DisassemblerView::showMenu(const QPoint&)
{
    if(RD_IsBusy()) return;
    m_contextmenu->exec(QCursor::pos());
}

void DisassemblerView::showGoto()
{
    // if(r_disasm->busy()) return;
    // GotoDialog dlggoto(m_disassembler, this);
    // connect(&dlggoto, &GotoDialog::symbolSelected, this, &DisassemblerView::goTo);

    // if((dlggoto.exec() != GotoDialog::Accepted) || !dlggoto.hasValidAddress())
    //     return;

    // if(r_doc->goTo(dlggoto.address()))
    //     return;

    // this->selectToHexDump(dlggoto.address(), m_disassembler->assembler()->addressWidth());
}

void DisassemblerView::goForward()
{
    RDCursor* cur = this->activeCursor();
    if(cur) RDCursor_GoForward(cur);
}
void DisassemblerView::goBack()
{
    RDCursor* cur = this->activeCursor();
    if(cur) RDCursor_GoBack(cur);
}

bool DisassemblerView::itemFromIndex(const QModelIndex &index, RDDocumentItem* item) const
{
    const ListingFilterModel* filtermodel = dynamic_cast<const ListingFilterModel*>(index.model());

    if(filtermodel)
    {
        *item = filtermodel->item(index);
        return true;
    }

    const CallTreeModel* calltreemodel = dynamic_cast<const CallTreeModel*>(index.model());

    if(calltreemodel)
    {
        //*item = calltreemodel->item(index);
        //return true;
    }

    const GotoModel* gotomodel = dynamic_cast<const GotoModel*>(index.model());

    if(gotomodel)
    {
        RDDocument* doc = RDDisassembler_GetDocument(m_disassembler);
        return RDDocument_GetItemAt(doc, static_cast<size_t>(index.row()), item);
    }

    return false;
}

void DisassemblerView::syncHexEdit()
{
    // REDasm::ListingItem item = r_doc->currentItem();

    // offset_location offset;
    // size_t len = 0;

    // if(item.isValid())
    // {
    //     offset = m_disassembler->loader()->offset(item.address);

    //     bool canbeinstruction = true;
    //     const REDasm::Symbol* symbol = nullptr;

    //     if(item.is(REDasm::ListingItem::SymbolItem))
    //     {
    //         symbol = r_doc->symbol(item.address);
    //         canbeinstruction = symbol->isLabel();
    //     }
    //     else if(item.is(REDasm::ListingItem::SegmentItem))
    //         canbeinstruction = false;

    //     if(canbeinstruction)
    //     {
    //         REDasm::CachedInstruction instruction = r_doc->instruction(item.address);

    //         if(!instruction)
    //             return;

    //         len = instruction->size;
    //     }
    //     else if(symbol)
    //         len = m_disassembler->assembler()->addressWidth();
    // }

    // if(!offset.valid) return;

    // QHexCursor* cursor = ui->hexView->document()->cursor();
    // cursor->selectOffset(offset, len);
}

void DisassemblerView::createActions()
{
    m_contextmenu = new QMenu(this);
    m_actsetfilter = m_contextmenu->addAction("Set Filter", this, &DisassemblerView::showFilter);
    this->addAction(m_actsetfilter);

    m_contextmenu->addSeparator();
    m_contextmenu->addAction("Cross References", this, &DisassemblerView::showModelReferences);
    m_contextmenu->addAction("Goto", [&]() { this->goTo(m_currentindex); });
}

ListingFilterModel *DisassemblerView::getSelectedFilterModel()
{
    if(ui->tabView->currentWidget() == ui->tabListing) return m_docks->functionsModel();
    if(ui->tabView->currentWidget() == ui->tabSegments) return m_segmentsmodel;
    if(ui->tabView->currentWidget() == ui->tabImports) return m_importsmodel;
    if(ui->tabView->currentWidget() == ui->tabExports) return m_exportsmodel;
    if(ui->tabView->currentWidget() == ui->tabStrings) return m_stringsmodel;
    return nullptr;
}

QString DisassemblerView::currentWord() const
{
    //if(ui->stackedWidget->currentWidget() == m_graphview)
        //return m_graphview->currentWord();

    return m_listingview->textView()->currentWord();
}

RDCursor* DisassemblerView::activeCursor() const { return m_listingview->textView()->activeCursor(); }
bool DisassemblerView::getCurrentItem(RDDocumentItem* item) const { return m_listingview->textView()->getCurrentItem(item); }
