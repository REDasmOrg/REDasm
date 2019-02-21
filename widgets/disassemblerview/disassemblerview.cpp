#include "disassemblerview.h"
#include "ui_disassemblerview.h"
#include "../../dialogs/referencesdialog.h"
#include "../../themeprovider.h"
#include <QHexView/document/buffer/qmemoryrefbuffer.h>
#include <QMessageBox>
#include <QPushButton>

DisassemblerView::DisassemblerView(QLineEdit *lefilter, QWidget *parent) : QWidget(parent), ui(new Ui::DisassemblerView), m_hexdocument(NULL), m_lefilter(lefilter)
{
    ui->setupUi(this);

    m_actions = new DisassemblerViewActions(this);
    m_docks = new DisassemblerViewDocks(this);

    m_listingview = new DisassemblerListingView(ui->stackedWidget);
    m_graphview = new DisassemblerGraphView(ui->stackedWidget);

    ui->hexView->setReadOnly(true);
    ui->hexView->setFrameShape(QFrame::NoFrame);

    ui->stackedWidget->addWidget(m_listingview);
    ui->stackedWidget->addWidget(m_graphview);

    m_importsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItem::SymbolItem, ui->tvImports);
    static_cast<SymbolTableModel*>(m_importsmodel->sourceModel())->setSymbolFlags(REDasm::SymbolTypes::ImportMask);
    ui->tvImports->setModel(m_importsmodel);

    m_exportsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItem::AllItems, ui->tvExports);
    static_cast<SymbolTableModel*>(m_exportsmodel->sourceModel())->setSymbolFlags(REDasm::SymbolTypes::ExportMask);
    ui->tvExports->setModel(m_exportsmodel);

    m_stringsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItem::SymbolItem, ui->tvStrings);
    static_cast<SymbolTableModel*>(m_stringsmodel->sourceModel())->setSymbolFlags(REDasm::SymbolTypes::StringMask);
    ui->tvStrings->setModel(m_stringsmodel);

    m_segmentsmodel = ListingFilterModel::createFilter<SegmentsModel>(ui->tvSegments);
    ui->tvSegments->setModel(m_segmentsmodel);

    ui->tvSegments->verticalHeader()->setDefaultSectionSize(ui->tvSegments->fontMetrics().lineSpacing());
    ui->tvImports->verticalHeader()->setDefaultSectionSize(ui->tvImports->fontMetrics().lineSpacing());
    ui->tvExports->verticalHeader()->setDefaultSectionSize(ui->tvExports->fontMetrics().lineSpacing());
    ui->tvStrings->verticalHeader()->setDefaultSectionSize(ui->tvStrings->fontMetrics().lineSpacing());

    ui->tvSegments->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
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

    connect(m_listingview->textView(), &DisassemblerTextView::gotoRequested, this, &DisassemblerView::showGoto);
    connect(m_listingview->textView(), &DisassemblerTextView::hexDumpRequested, this, &DisassemblerView::selectToHexDump);
    connect(m_listingview->textView(), &DisassemblerTextView::referencesRequested, this, &DisassemblerView::showReferences);
    connect(m_listingview->textView(), &DisassemblerTextView::addressChanged, this, &DisassemblerView::displayAddress);
    connect(m_listingview->textView(), &DisassemblerTextView::addressChanged, this, &DisassemblerView::displayCurrentReferences);
    connect(m_listingview->textView(), &DisassemblerTextView::switchView, this, &DisassemblerView::switchGraphListing);
    connect(m_listingview->textView(), &DisassemblerTextView::switchToHexDump, this, &DisassemblerView::switchToHexDump);
    connect(m_listingview->textView(), &DisassemblerTextView::addressChanged, m_docks, &DisassemblerViewDocks::updateCallGraph);

    connect(m_listingview->textView(), &DisassemblerTextView::canGoBackChanged, this, [=]() {
        m_actions->setEnabled(DisassemblerViewActions::BackAction, m_listingview->textView()->canGoBack());
    });

    connect(m_listingview->textView(), &DisassemblerTextView::canGoForwardChanged, this, [=]() {
        m_actions->setEnabled(DisassemblerViewActions::ForwardAction, m_listingview->textView()->canGoForward());
    });

    connect(m_graphview, &DisassemblerGraphView::addressChanged, this, &DisassemblerView::displayAddress);
    connect(m_graphview, &DisassemblerGraphView::addressChanged, this, &DisassemblerView::displayCurrentReferences);
    connect(m_graphview, &DisassemblerGraphView::referencesRequested, this, &DisassemblerView::showReferences);
    connect(m_graphview, &DisassemblerGraphView::switchView, this, &DisassemblerView::switchGraphListing);
    connect(m_graphview, &DisassemblerGraphView::addressChanged, m_docks, &DisassemblerViewDocks::updateCallGraph);

    connect(m_actions, &DisassemblerViewActions::backRequested, m_listingview->textView(), &DisassemblerTextView::goBack);
    connect(m_actions, &DisassemblerViewActions::forwardRequested, m_listingview->textView(), &DisassemblerTextView::goForward);
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

void DisassemblerView::setDisassembler(REDasm::Disassembler *disassembler)
{
    m_disassembler = std::unique_ptr<REDasm::Disassembler>(disassembler); // Take ownership

    REDasm::log(QString("Found format '%1' with '%2' instruction set").arg(S_TO_QS(disassembler->format()->name()),
                                                                           S_TO_QS(disassembler->assembler()->name())).toStdString());

    m_docks->setDisassembler(disassembler);
    m_importsmodel->setDisassembler(disassembler);
    m_exportsmodel->setDisassembler(disassembler);
    m_stringsmodel->setDisassembler(disassembler);
    m_segmentsmodel->setDisassembler(disassembler);

    REDasm::AbstractBuffer* buffer = disassembler->format()->buffer();
    m_hexdocument = QHexDocument::fromMemory<QMemoryRefBuffer>(reinterpret_cast<char*>(buffer->data()), buffer->size(), ui->hexView);
    ui->hexView->setDocument(m_hexdocument);

    m_listingview->setDisassembler(disassembler);
    m_graphview->setDisassembler(disassembler);

    ui->stackedWidget->currentWidget()->setFocus();

    disassembler->busyChanged += [&]() {
        QMetaObject::invokeMethod(this, "checkDisassemblerStatus", Qt::QueuedConnection);
    };

    if(disassembler->busy())
        return;

    this->checkDisassemblerStatus();
}

void DisassemblerView::changeDisassemblerStatus()
{
    if(m_disassembler->state() == REDasm::Job::ActiveState)
        m_disassembler->pause();
    else if(m_disassembler->state() == REDasm::Job::PausedState)
        m_disassembler->resume();
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
    m_actsetfilter->setVisible(index.isValid() && (index.model() != m_docks->callGraphModel()));
}

void DisassemblerView::checkHexEdit(int index)
{
    QWidget* w = ui->tabView->widget(index);

    if(!w || (w != ui->tabHexDump))
        return;

    this->syncHexEdit();
}

void DisassemblerView::updateCurrentFilter(int index)
{
    QWidget* w = ui->tabView->widget(index);

    if(!w)
        return;

    if(w == ui->tabSegments)
        m_segmentsmodel->setFilter(m_lefilter->text());
    else if(w == ui->tabImports)
        m_importsmodel->setFilter(m_lefilter->text());
    else if(w == ui->tabExports)
        m_exportsmodel->setFilter(m_lefilter->text());
    else if(w == ui->tabStrings)
        m_stringsmodel->setFilter(m_lefilter->text());
}

void DisassemblerView::gotoXRef(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    ui->tabView->setCurrentWidget(ui->tabListing);
    m_listingview->textView()->goTo(static_cast<address_t>(index.internalId()));
    this->showListingOrGraph();
}

void DisassemblerView::goTo(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(index.internalPointer());
    m_listingview->textView()->goTo(item);

    if(ui->stackedWidget->currentWidget() == m_graphview)
        m_graphview->graph();

    this->showListingOrGraph();
}

void DisassemblerView::showModelReferences()
{
    if(!m_currentindex.isValid() || !m_currentindex.internalPointer())
        return;

    REDasm::ListingItem* item = NULL;
    const QAbstractProxyModel* proxymodel = dynamic_cast<const QAbstractProxyModel*>(m_currentindex.model());

    if(proxymodel)
        item = reinterpret_cast<REDasm::ListingItem*>(proxymodel->mapToSource(m_currentindex).internalPointer());
    else
        item = reinterpret_cast<REDasm::ListingItem*>(m_currentindex.internalPointer());

    REDasm::SymbolPtr symbol;

    if(m_currentindex.model() == m_callgraphmodel)
    {
        REDasm::InstructionPtr instruction = m_disassembler->document()->instruction(item->address);
        symbol = m_disassembler->document()->symbol(instruction->target());
    }
    else
        symbol = m_disassembler->document()->symbol(item->address);

    this->showReferences(symbol->address);
}

void DisassemblerView::showReferences(address_t address)
{
    REDasm::SymbolPtr symbol = m_disassembler->document()->symbol(address);

    if(!symbol)
        return;

    if(!m_disassembler->getReferencesCount(symbol->address))
    {
        QMessageBox::information(this, "No References", "There are no references to " + S_TO_QS(symbol->name));
        return;
    }

    ReferencesDialog dlgreferences(m_disassembler.get(), symbol, this);

    connect(&dlgreferences, &ReferencesDialog::jumpTo, this, [&](address_t address) {
        if(ui->stackedWidget->currentWidget() == m_graphview) {
            auto it = m_disassembler->document()->instructionItem(address);

            if(it != m_disassembler->document()->end()) {
                m_graphview->goTo(address);
                return;
            }

            this->switchGraphListing();
        }

        m_listingview->textView()->goTo(address);
        ui->tabView->setCurrentWidget(ui->tabListing);
    });

    dlgreferences.exec();
}

void DisassemblerView::displayAddress(address_t address)
{
    if(m_disassembler->busy())
        return;

    REDasm::ListingDocument& document = m_disassembler->document();
    REDasm::FormatPlugin* format = m_disassembler->format();
    const REDasm::Segment* segment = document->segment(address);
    REDasm::SymbolPtr functionstart = document->functionStartSymbol(address);

    QString segm = segment ? S_TO_QS(segment->name) : "???",
            offs = segment ? S_TO_QS(REDasm::hex(format->offset(address), format->bits())) : "???",
            addr = S_TO_QS(REDasm::hex(address, format->bits()));

    QString s = QString::fromWCharArray(L"<b>Address: </b>%1\u00A0\u00A0").arg(addr);
    s += QString::fromWCharArray(L"<b>Offset: </b>%1\u00A0\u00A0").arg(offs);
    s += QString::fromWCharArray(L"<b>Segment: </b>%1\u00A0\u00A0").arg(segm);

    REDasm::ListingItem* item = document->currentItem();

    if(item && item->is(REDasm::ListingItem::InstructionItem))
    {
        QString func = "???";

        if(functionstart)
        {
            func = S_TO_QS(functionstart->name);
            size_t offset = address - functionstart->address;

            if(offset)
                func += "+" + S_TO_QS(REDasm::hex(offset, 8));
        }

        s = QString::fromWCharArray(L"<b>Function: </b>%1\u00A0\u00A0").arg(func) + s;
    }

    REDasm::status(s.toStdString());
}

void DisassemblerView::displayCurrentReferences()
{
    REDasm::ListingDocument& document = m_disassembler->document();
    const std::string& word = document->cursor()->wordUnderCursor();

    if(!word.empty())
    {
        REDasm::SymbolPtr symbol = document->symbol(word);

        if(symbol)
        {
            m_docks->referencesModel()->xref(symbol->address);
            return;
        }
    }

    REDasm::ListingItem* item = document->itemAt(document->cursor()->currentLine());
    m_docks->referencesModel()->xref(item->address);
}

void DisassemblerView::switchGraphListing()
{
    if(ui->stackedWidget->currentWidget() == m_listingview)
    {
        m_actions->setIcon(DisassemblerViewActions::GraphListingAction, THEME_ICON("listing"));
        ui->stackedWidget->setCurrentWidget(m_graphview);
        m_graphview->graph();

    }
    else
    {
        m_actions->setIcon(DisassemblerViewActions::GraphListingAction, THEME_ICON("graph"));
        ui->stackedWidget->setCurrentWidget(m_listingview);
    }

    ui->stackedWidget->currentWidget()->setFocus();
}

void DisassemblerView::switchToHexDump()
{
    this->syncHexEdit();
    ui->tabView->setCurrentWidget(ui->tabHexDump);
}

void DisassemblerView::toggleFilter()
{
    if(m_lefilter->isVisible())
        this->clearFilter();
    else
        this->showFilter();
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
    if(!ui->tabView->currentIndex())
        return;

    ui->tabView->setCurrentIndex(0);
}

void DisassemblerView::showFilter()
{
    ListingFilterModel* filtermodel = this->getSelectedFilterModel();

    if(!filtermodel)
        return;

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
    offset_t offset = m_disassembler->format()->offset(address);
    ui->tabView->setCurrentWidget(ui->tabHexDump);

    QHexCursor* cursor = ui->hexView->document()->cursor();
    cursor->selectOffset(offset, len);
}

void DisassemblerView::showMenu(const QPoint&) { m_contextmenu->exec(QCursor::pos()); }

void DisassemblerView::showGoto()
{
    GotoDialog dlggoto(m_disassembler.get(), this);
    connect(&dlggoto, &GotoDialog::symbolSelected, this, &DisassemblerView::goTo);

    if((dlggoto.exec() != GotoDialog::Accepted) || !dlggoto.hasValidAddress())
        return;

    if(m_listingview->textView()->goTo(dlggoto.address()))
        return;

    this->selectToHexDump(dlggoto.address(), m_disassembler->format()->addressWidth());
}

void DisassemblerView::syncHexEdit()
{
    REDasm::ListingDocument& document = m_disassembler->document();
    REDasm::ListingItem* item = document->currentItem();

    offset_t offset = 0;
    u64 len = 0;

    if(item)
    {
        offset = m_disassembler->format()->offset(item->address);

        bool canbeinstruction = true;
        REDasm::SymbolPtr symbol;

        if(item->is(REDasm::ListingItem::SymbolItem))
        {
            symbol = document->symbol(item->address);
            canbeinstruction = symbol->is(REDasm::SymbolTypes::Code);
        }
        else if(item->is(REDasm::ListingItem::SegmentItem))
            canbeinstruction = false;

        if(canbeinstruction)
        {
            REDasm::InstructionPtr instruction = document->instruction(item->address);
            len = instruction->size;
        }
        else if(symbol)
            len = m_disassembler->format()->addressWidth();
    }

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
    if(ui->tabView->currentWidget() == ui->tabListing)
        return m_docks->functionsModel();
    else if(ui->tabView->currentWidget() == ui->tabSegments)
        return m_segmentsmodel;
    else if(ui->tabView->currentWidget() == ui->tabImports)
        return m_importsmodel;
    else if(ui->tabView->currentWidget() == ui->tabExports)
        return m_exportsmodel;
    else if(ui->tabView->currentWidget() == ui->tabStrings)
        return m_stringsmodel;

    return NULL;
}
