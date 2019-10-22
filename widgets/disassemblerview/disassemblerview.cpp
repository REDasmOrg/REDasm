#include "disassemblerview.h"
#include "ui_disassemblerview.h"
#include "../../dialogs/dev/iteminformationdialog/iteminformationdialog.h"
#include "../../dialogs/referencesdialog/referencesdialog.h"
#include "../../themeprovider.h"
#include "../../redasmsettings.h"
#include <redasm/context.h>
#include <redasm/support/utils.h>
#include <redasm/plugins/loader/loader.h>
#include <redasm/plugins/assembler/assembler.h>
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

    m_importsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItemType::SymbolItem, ui->tvImports);
    static_cast<SymbolTableModel*>(m_importsmodel->sourceModel())->setSymbolType(REDasm::SymbolType::ImportNew);
    ui->tvImports->setModel(m_importsmodel);

    m_exportsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItemType::AllItems, ui->tvExports);
    static_cast<SymbolTableModel*>(m_exportsmodel->sourceModel())->setSymbolType(REDasm::SymbolType::FunctionNew);
    static_cast<SymbolTableModel*>(m_exportsmodel->sourceModel())->setSymbolFlags(REDasm::SymbolFlags::Export);
    ui->tvExports->setModel(m_exportsmodel);

    m_stringsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItemType::SymbolItem, ui->tvStrings);
    static_cast<SymbolTableModel*>(m_stringsmodel->sourceModel())->setSymbolType(REDasm::SymbolType::StringNew);
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

DisassemblerView::~DisassemblerView() { delete ui; }
REDasm::Disassembler *DisassemblerView::disassembler() { return m_disassembler.get(); }

void DisassemblerView::bindDisassembler(REDasm::Disassembler *disassembler)
{
    m_disassembler = REDasm::DisassemblerPtr(disassembler); // Take ownership

    m_docks->setDisassembler(m_disassembler);
    m_importsmodel->setDisassembler(m_disassembler);
    m_exportsmodel->setDisassembler(m_disassembler);
    m_stringsmodel->setDisassembler(m_disassembler);
    m_segmentsmodel->setDisassembler(m_disassembler);

    REDasm::AbstractBuffer* buffer = r_ldr->buffer();
    m_hexdocument = QHexDocument::fromMemory<QMemoryRefBuffer>(reinterpret_cast<char*>(buffer->data()), buffer->size(), ui->hexView);
    ui->hexView->setDocument(m_hexdocument);

    m_listingview->setDisassembler(m_disassembler);
    m_graphview->setDisassembler(m_disassembler);

    ui->stackedWidget->currentWidget()->setFocus();

    m_disassembler->busyChanged.connect(this, [&](REDasm::EventArgs*) {
        QMetaObject::invokeMethod(this, "checkDisassemblerStatus", Qt::QueuedConnection);
    });

    r_docnew->cursor().backChanged.connect(this, [&](REDasm::EventArgs*) {
        m_actions->setEnabled(DisassemblerViewActions::BackAction, r_docnew->cursor().canGoBack());
    });

    r_docnew->cursor().forwardChanged.connect(this, [&](REDasm::EventArgs*) {
        m_actions->setEnabled(DisassemblerViewActions::ForwardAction, r_docnew->cursor().canGoForward());
    });

    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::gotoDialogRequested, this, &DisassemblerView::showGoto);
    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::hexDumpRequested, this, &DisassemblerView::selectToHexDump);
    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::referencesRequested, this, &DisassemblerView::showReferences);
    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::switchToHexDump, this, &DisassemblerView::switchToHexDump);
    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::itemInformationRequested, this, &DisassemblerView::showCurrentItemInfo);
    connect(m_listingview->textView()->disassemblerActions(), &DisassemblerActions::callGraphRequested, m_docks, &DisassemblerViewDocks::initializeCallGraph);

    m_actions->setEnabled(DisassemblerViewActions::BackAction, r_docnew->cursor().canGoBack());
    m_actions->setEnabled(DisassemblerViewActions::ForwardAction, r_docnew->cursor().canGoForward());
}

void DisassemblerView::hideActions() { if(m_actions) m_actions->hideActions(); }

void DisassemblerView::changeDisassemblerStatus()
{
    switch(r_disasm->state())
    {
        case REDasm::JobState::ActiveState: m_disassembler->pause(); break;
        case REDasm::JobState::PausedState: m_disassembler->resume(); break;
        default: break;
    }
}

void DisassemblerView::checkDisassemblerStatus()
{
    m_actsetfilter->setEnabled(!m_disassembler->busy());
    m_lefilter->setEnabled(!m_disassembler->busy());

    m_actions->setEnabled(DisassemblerViewActions::GotoAction, !m_disassembler->busy());
    m_actions->setEnabled(DisassemblerViewActions::GraphListingAction, !m_disassembler->busy());
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

    if(w == ui->tabSegments) m_segmentsmodel->setFilter(m_lefilter->text());
    else if(w == ui->tabImports) m_importsmodel->setFilter(m_lefilter->text());
    else if(w == ui->tabExports) m_exportsmodel->setFilter(m_lefilter->text());
    else if(w == ui->tabStrings) m_stringsmodel->setFilter(m_lefilter->text());
}

void DisassemblerView::gotoXRef(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalId())
        return;

    ui->tabView->setCurrentWidget(ui->tabListing);
    r_docnew->goTo(static_cast<address_t>(index.internalId()));
}

void DisassemblerView::goTo(const QModelIndex &index)
{
    if(!index.isValid()) return;

    REDasm::ListingItem item = this->itemFromIndex(index);
    if(!item.isValid()) return;

    r_docnew->goTo(item);

    if(!m_graphview->isCursorInGraph())
        ui->stackedWidget->setCurrentWidget(m_listingview);

    this->showListingOrGraph();
}

void DisassemblerView::showModelReferences()
{
    if(!m_currentindex.isValid()) return;

    REDasm::ListingItem item = this->itemFromIndex(m_currentindex);
    if(!item.isValid()) return;

    const REDasm::Symbol* symbol = nullptr;

    if(m_currentindex.model() == m_docks->callTreeModel())
    {
        REDasm::CachedInstruction instruction = r_docnew->instruction(item.address_new);
        symbol = r_docnew->symbol(r_disasm->getTarget(instruction->address));
    }
    else
        symbol = r_docnew->symbol(item.address_new);

    this->showReferences(symbol->address);
}

void DisassemblerView::showCurrentItemInfo()
{
    ItemInformationDialog dlgiteminfo(m_disassembler, this);
    dlgiteminfo.exec();
}

void DisassemblerView::showReferences(address_t address)
{
    const REDasm::Symbol* symbol = r_docnew->symbol(address);
    if(!symbol) return;

    if(!r_disasm->getReferencesCount(symbol->address))
    {
        QMessageBox::information(this, "No References", "There are no references to " + S_TO_QS(symbol->name));
        return;
    }

    ReferencesDialog dlgreferences(symbol, this);

    connect(&dlgreferences, &ReferencesDialog::jumpTo, this, [&](address_t address) {
        if(ui->stackedWidget->currentWidget() == m_graphview) {
            if(r_docnew->itemInstruction(address).isValid()) {
                m_graphview->goTo(address);
                return;
            }

            this->switchGraphListing();
        }

        r_docnew->goTo(address);
        ui->tabView->setCurrentWidget(ui->tabListing);
    });

    dlgreferences.exec();
}

void DisassemblerView::displayAddress(address_t address)
{
    if(r_disasm->busy()) return;

    const REDasm::Segment* segment = r_docnew->segment(address);
    const REDasm::Symbol* functionstart = r_docnew->functionStartSymbol(address);
    offset_location offset = r_ldr->offset(address);

    QString segm = segment ? S_TO_QS(segment->name) : "UNKNOWN",
            offs = segment && offset.valid ? S_TO_QS(REDasm::String::hex(offset.value, r_asm->bits())) : "UNKNOWN",
            addr = S_TO_QS(REDasm::String::hex(address, r_asm->bits()));

    QString s = QString::fromWCharArray(L"<b>Address: </b>%1\u00A0\u00A0").arg(addr);
    s += QString::fromWCharArray(L"<b>Offset: </b>%1\u00A0\u00A0").arg(offs);
    s += QString::fromWCharArray(L"<b>Segment: </b>%1\u00A0\u00A0").arg(segm);

    if(r_docnew->currentItem().isValid() && functionstart)
    {
        QString func = S_TO_QS(functionstart->name);

        if(address > functionstart->address)
            func += "+" + S_TO_QS(REDasm::String::hex(address - functionstart->address, 8));
        else if(address < functionstart->address)
            func += S_TO_QS(REDasm::String::hex<REDasm::signed_of<size_t>::type>(address - functionstart->address));

        s = QString::fromWCharArray(L"<b>Function: </b>%1\u00A0\u00A0").arg(func) + s;
    }

    r_ctx->status(qUtf8Printable(s));
}

void DisassemblerView::displayCurrentReferences()
{
    REDasm::String word = this->currentWord();

    if(!word.empty())
    {
        const REDasm::Symbol* symbol = r_docnew->symbol(word);

        if(symbol)
        {
            m_docks->referencesModel()->xref(symbol->address);
            return;
        }
    }

    REDasm::ListingItem item = r_docnew->itemAt(r_docnew->cursor().currentLine());
    m_docks->referencesModel()->xref(item.address_new);
}

void DisassemblerView::switchGraphListing()
{
    if(r_disasm->busy()) return;

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

    if(!filtermodel)
        return;

    filtermodel->setFilter(m_lefilter->text());
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

    m_docks->functionsModel()->clearFilter();
    m_segmentsmodel->clearFilter();
    m_importsmodel->clearFilter();
    m_exportsmodel->clearFilter();
    m_stringsmodel->clearFilter();
}

void DisassemblerView::selectToHexDump(address_t address, u64 len)
{
    offset_location offset = m_disassembler->loader()->offset(address);
    if(!offset.valid) return;

    ui->tabView->setCurrentWidget(ui->tabHexDump);

    QHexCursor* cursor = ui->hexView->document()->cursor();
    cursor->selectOffset(offset, len);
}

void DisassemblerView::showMenu(const QPoint&)
{
    if(m_disassembler->busy())
        return;

    m_contextmenu->exec(QCursor::pos());
}

void DisassemblerView::showGoto()
{
    if(m_disassembler->busy())
        return;

    GotoDialog dlggoto(m_disassembler, this);
    connect(&dlggoto, &GotoDialog::symbolSelected, this, &DisassemblerView::goTo);

    if((dlggoto.exec() != GotoDialog::Accepted) || !dlggoto.hasValidAddress())
        return;

    if(r_docnew->goTo(dlggoto.address()))
        return;

    this->selectToHexDump(dlggoto.address(), m_disassembler->assembler()->addressWidth());
}

void DisassemblerView::goForward() { r_docnew->cursor().goForward(); }
void DisassemblerView::goBack() { r_docnew->cursor().goBack(); }

REDasm::ListingItem DisassemblerView::itemFromIndex(const QModelIndex &index) const
{
    const ListingFilterModel* filtermodel = dynamic_cast<const ListingFilterModel*>(index.model());

    if(filtermodel)
        return filtermodel->item(index);

    const GotoModel* gotomodel = dynamic_cast<const GotoModel*>(index.model());
    if(gotomodel) return r_docnew->itemAt(index.row());
    return REDasm::ListingItem();
}

void DisassemblerView::syncHexEdit()
{
    REDasm::ListingItem item = r_docnew->currentItem();

    offset_location offset;
    size_t len = 0;

    if(item.isValid())
    {
        offset = m_disassembler->loader()->offset(item.address_new);

        bool canbeinstruction = true;
        const REDasm::Symbol* symbol = nullptr;

        if(item.is(REDasm::ListingItemType::SymbolItem))
        {
            symbol = r_docnew->symbol(item.address_new);
            canbeinstruction = symbol->is(REDasm::SymbolType::LabelNew);
        }
        else if(item.is(REDasm::ListingItemType::SegmentItem))
            canbeinstruction = false;

        if(canbeinstruction)
        {
            REDasm::CachedInstruction instruction = r_docnew->instruction(item.address_new);

            if(!instruction)
                return;

            len = instruction->size;
        }
        else if(symbol)
            len = m_disassembler->assembler()->addressWidth();
    }

    if(!offset.valid) return;

    QHexCursor* cursor = ui->hexView->document()->cursor();
    cursor->selectOffset(offset, len);
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

REDasm::String DisassemblerView::currentWord() const
{
    if(ui->stackedWidget->currentWidget() == m_graphview)
        return m_graphview->currentWord();

    return m_listingview->textView()->currentWord();
}
