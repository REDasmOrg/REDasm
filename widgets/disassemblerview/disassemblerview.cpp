#include "disassemblerview.h"
#include "ui_disassemblerview.h"
#include "../../dialogs/referencesdialog.h"
#include <QMessageBox>

#define VMIL_TAB_INDEX 1

DisassemblerView::DisassemblerView(QLabel *lblstatus, QWidget *parent) : QWidget(parent), ui(new Ui::DisassemblerView), m_hexdocument(NULL), m_lblstatus(lblstatus), m_disassembler(NULL)
{
    ui->setupUi(this);

    ui->vSplitter->setSizes((QList<int>() << this->width() * 0.70
                                          << this->width() * 0.30));

    ui->vSplitter2->setSizes((QList<int>() << this->width() * 0.70
                                           << this->width() * 0.30));

    ui->hSplitter->setSizes((QList<int>() << this->width() * 0.30
                                          << this->width() * 0.70));

    ui->hexEdit->setReadOnly(true);
    ui->hexEdit->setFrameShape(QFrame::NoFrame);

    ui->topTabs->removeTab(VMIL_TAB_INDEX); // Hide VMIL tab by default

    ui->tbBack->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Left));
    ui->tbForward->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Right));
    ui->tbGoto->setShortcut(QKeySequence(Qt::Key_G));

    m_functionsmodel = ListingFilterModel::createFilter<ListingItemModel>(REDasm::ListingItem::FunctionItem, ui->tvFunctions);
    static_cast<ListingItemModel*>(m_functionsmodel->sourceModel())->setDefaultFont(true);
    ui->tvFunctions->setModel(m_functionsmodel);

    m_importsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::SymbolTypes::ImportMask, ui->tvFunctions);
    ui->tvImports->setModel(m_importsmodel);

    m_exportsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::SymbolTypes::ExportMask, ui->tvFunctions);
    ui->tvExports->setModel(m_exportsmodel);

    m_stringsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::SymbolTypes::StringMask, ui->tvStrings);
    ui->tvStrings->setModel(m_stringsmodel);

    m_segmentsmodel = ListingFilterModel::createFilter<SegmentsModel>(ui->tvSegments);
    ui->tvSegments->setModel(m_segmentsmodel);

    m_referencesmodel = new ReferencesModel(ui->tvReferences);
    ui->tvReferences->setModel(m_referencesmodel);

    ui->tvFunctions->setColumnHidden(3, true);
    ui->tvFunctions->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvFunctions->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvFunctions->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->tvFunctions->header()->moveSection(2, 1);

    //ui->tvReferences->setColumnHidden(0, true);
    //ui->tvReferences->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    //ui->tvReferences->header()->setSectionResizeMode(2, QHeaderView::Stretch);

    ui->tvSegments->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    ui->tvImports->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvImports->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvImports->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->tvExports->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvExports->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvExports->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->tvStrings->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvStrings->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvStrings->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);

    connect(ui->disassemblerTextView, &DisassemblerTextView::gotoRequested, this, &DisassemblerView::showGoto);
    connect(ui->disassemblerTextView, &DisassemblerTextView::hexDumpRequested, this, &DisassemblerView::showHexDump);
    connect(ui->disassemblerTextView, &DisassemblerTextView::symbolRenamed, this, &DisassemblerView::updateModel);
    connect(ui->disassemblerTextView, &DisassemblerTextView::addressChanged, this, &DisassemblerView::displayAddress);
    connect(ui->disassemblerTextView, &DisassemblerTextView::addressChanged, this, &DisassemblerView::displayInstructionReferences);
    connect(ui->disassemblerTextView, &DisassemblerTextView::symbolAddressChanged, this, &DisassemblerView::displayReferences);
    connect(ui->disassemblerTextView, &DisassemblerTextView::symbolDeselected, m_referencesmodel, &ReferencesModel::clear);
    connect(ui->disassemblerTextView, &DisassemblerTextView::invalidateSymbols, [this]() { this->updateModel(NULL);});
    connect(ui->disassemblerTextView, &DisassemblerTextView::canGoBackChanged, [this]() { ui->tbBack->setEnabled(ui->disassemblerTextView->canGoBack()); });
    connect(ui->disassemblerTextView, &DisassemblerTextView::canGoForwardChanged, [this]() { ui->tbForward->setEnabled(ui->disassemblerTextView->canGoForward()); });

    connect(ui->tbBack, &QToolButton::clicked, ui->disassemblerTextView, &DisassemblerTextView::goBack);
    connect(ui->tbForward, &QToolButton::clicked, ui->disassemblerTextView, &DisassemblerTextView::goForward);
    connect(ui->tbGoto, &QToolButton::clicked, this, &DisassemblerView::showGoto);

    connect(ui->tvReferences, &QTreeView::doubleClicked, this, &DisassemblerView::gotoXRef);
    connect(ui->tvFunctions, &QTreeView::doubleClicked, this, &DisassemblerView::gotoSymbol);
    connect(ui->tvFunctions, &QTreeView::customContextMenuRequested, this, &DisassemblerView::showMenu);
    connect(ui->tvExports, &QTableView::doubleClicked, this, &DisassemblerView::gotoSymbol);
    connect(ui->tvExports, &QTableView::customContextMenuRequested, this, &DisassemblerView::showMenu);
    connect(ui->tvImports, &QTableView::doubleClicked, this, &DisassemblerView::gotoSymbol);
    connect(ui->tvImports, &QTableView::customContextMenuRequested, this, &DisassemblerView::showMenu);
    connect(ui->tvStrings, &QTableView::doubleClicked, this, &DisassemblerView::gotoSymbol);
    connect(ui->tvStrings, &QTableView::customContextMenuRequested, this, &DisassemblerView::showMenu);

    connect(ui->leFilter, &QLineEdit::textChanged, [this](const QString&) { this->filterSymbols(); });
    connect(ui->leFunctionFilter, &QLineEdit::textChanged, [this](const QString&) { this->filterFunctions(); });

    REDasm::setLoggerCallback([this](const std::string& s) {
        QMetaObject::invokeMethod(this, "log", Qt::QueuedConnection, Q_ARG(QString, S_TO_QS(s)));
    });

    this->createMenu();
}

DisassemblerView::~DisassemblerView()
{
    delete ui;

    if(m_disassembler)
        delete m_disassembler;
}

void DisassemblerView::setDisassembler(REDasm::Disassembler *disassembler)
{
    m_disassembler = disassembler;
    this->log(QString("Found format '%1' with '%2'").arg(S_TO_QS(disassembler->format()->name()),
                                                         S_TO_QS(disassembler->assembler()->name())));

    REDasm::Buffer& buffer = disassembler->buffer();
    m_hexdocument = QHexDocument::fromMemory(reinterpret_cast<const char*>(buffer.data), buffer.length);
    m_hexdocument->setParent(this);

    m_functionsmodel->setDisassembler(disassembler);
    m_importsmodel->setDisassembler(disassembler);
    m_exportsmodel->setDisassembler(disassembler);
    m_stringsmodel->setDisassembler(disassembler);
    m_segmentsmodel->setDisassembler(disassembler);
    //m_referencesmodel->setDisassembler(disassembler);

    ui->hexEdit->setDocument(m_hexdocument);
    ui->bottomTabs->setCurrentWidget(ui->tabOutput);
    ui->disassemblerTextView->setDisassembler(disassembler);
    //FIXME: ui->disassemblerGraphView->setDisassembler(disassembler);

    disassembler->disassemble();
}

bool DisassemblerView::busy() const
{
    return false; // FIXME: !!!
}

void DisassemblerView::on_topTabs_currentChanged(int index)
{
    QWidget* w = ui->topTabs->widget(index);

    if(!w)
        return;

    //if(w == ui->tabVMIL)
        //ui->vmilTextView->goTo(ui->disassemblerTextView->currentAddress());
    //else if(w == ui->disassemblerGraphView)
        //ui->disassemblerGraphView->display(ui->disassemblerTextView->currentAddress());
}

void DisassemblerView::on_bottomTabs_currentChanged(int index)
{
    QWidget* w = ui->bottomTabs->widget(index);

    if(!w || ((w == ui->tabSegments) || (w == ui->tabOutput) || (w == ui->hexEdit)))
    {
        ui->leFilter->setEnabled(false);
        ui->leFilter->clear();
        return;
    }

    /*
    if(w == ui->tabImports)
        ui->leFilter->setText(m_importsmodel->filterName());
    else if(w == ui->tabExports)
        ui->leFilter->setText(m_exportsmodel->filterName());
    else if(w == ui->tabStrings)
        ui->leFilter->setText(m_stringsmodel->filterName());
    */

    ui->leFilter->setEnabled(true);
}

void DisassemblerView::gotoXRef(const QModelIndex &index)
{
    /*
    if(!index.isValid() || !index.internalPointer())
        return;

    address_t address = static_cast<address_t>(index.internalId());
    const REDasm::Segment* segment = this->_disassembler->format()->segment(address);

    if(!segment)
        return;

    ui->disassemblerTextView->goTo(address);
    */
}

void DisassemblerView::gotoSymbol(const QModelIndex &index)
{
    /*
    if(!index.isValid() || !index.internalPointer())
        return;

    const SymbolTableFilterModel* filtermodel = static_cast<const SymbolTableFilterModel*>(index.model());
    QModelIndex srcindex = filtermodel->mapToSource(index);
    REDasm::SymbolPtr symbol = filtermodel->symbol(srcindex);
    const REDasm::Segment* segment = this->_disassembler->format()->segment(symbol->address);

    if(!segment)
        return;

    ui->disassemblerTextView->goTo(symbol);
    */
}

void DisassemblerView::xrefSymbol(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    /*
    const ListingDocumentFilterModel* filtermodel = static_cast<const ListingDocumentFilterModel*>(index.model());
    QModelIndex srcindex = filtermodel->mapToSource(index);
    REDasm::SymbolPtr symbol = filtermodel->symbol(srcindex);

    if(!m_disassembler->hasReferences(symbol))
    {
        QMessageBox::information(this, "No References", "There are no references to " + S_TO_QS(symbol->name));
        return;
    }

    ReferencesDialog dlgreferences(m_disassembler, ui->disassemblerTextView->currentAddress(), symbol, this);
    connect(&dlgreferences, &ReferencesDialog::jumpTo, [this](address_t address) { ui->disassemblerTextView->goTo(address); });
    dlgreferences.exec();
    */
}

void DisassemblerView::displayAddress(address_t address)
{
    /*
    REDasm::SymbolPtr symbol = this->_disassembler->instructions().getFunction(address);
    const REDasm::Segment* segment = this->_disassembler->format()->segment(address);
    offset_t offset = this->_disassembler->format()->offset(address);
    s64 foffset = symbol ? address - symbol->address : 0;
    int bits = this->_disassembler->format()->bits();
    QString soffset;

    if(foffset > 0)
        soffset = "+" + QString::number(foffset, 16);
    else if(foffset < 0)
        soffset = "-" + QString::number(foffset, 16);

    QString s = QString("<b>%1:%2</b>\u00A0\u00A0[%3]\u00A0\u00A0<b>%4%5</b>").arg(segment ? S_TO_QS(segment->name) : "unk",
                                                                                   S_TO_QS(REDasm::hex(address, bits, false)),
                                                                                   S_TO_QS(REDasm::hex(offset, bits, false)),
                                                                                   symbol ? S_TO_QS(symbol->name) : QString(),
                                                                                   soffset);

    this->_lblstatus->setText(s);
    */
}

void DisassemblerView::displayInstructionReferences()
{
    /*
    REDasm::InstructionsPool& listing = this->_disassembler->instructions();
    auto it = listing.find(ui->disassemblerTextView->currentAddress());

    if(it == listing.end())
    {
        this->_referencesmodel->clear();
        return;
    }

    this->_referencesmodel->xref(*it);
    */
}

void DisassemblerView::displayReferences()
{
    //REDasm::SymbolPtr symbol = this->_disassembler->symbolTable()->symbol(ui->disassemblerTextView->symbolAddress());
    //this->_referencesmodel->xref(ui->disassemblerTextView->currentAddress(), symbol);
}

void DisassemblerView::updateModel(const REDasm::SymbolPtr &symbol)
{
    /*
    if(!symbol)
    {
        m_functionsmodel->reloadSymbols();
        m_stringsmodel->reloadSymbols();
        return;
    }

    if(symbol->isFunction())
    {
        m_functionsmodel->reloadSymbols();
        m_exportsmodel->reloadSymbols();
    }
    else if(symbol->is(REDasm::SymbolTypes::ImportMask))
        m_importsmodel->reloadSymbols();
    else if(symbol->is(REDasm::SymbolTypes::String))
        m_stringsmodel->reloadSymbols();
        */
}

void DisassemblerView::log(const QString &s)
{
    ui->pteOutput->insertPlainText(s + "\n");
}

void DisassemblerView::filterFunctions()
{
    QString s = ui->leFunctionFilter->text();

    if(s.length() == 1)
        return;

    //FIXME: m_functionsmodel->setFilterName(s);
}

void DisassemblerView::filterSymbols()
{
    QString s = ui->leFilter->text();

    if(s.length() == 1)
        return;

    QWidget* w = ui->bottomTabs->currentWidget();

    /*
    if(w == ui->tabImports)
        m_importsmodel->setFilterName(s);
    else if(w == ui->tabExports)
        m_exportsmodel->setFilterName(s);
    else if(w == ui->tabStrings)
        m_stringsmodel->setFilterName(s);
    */
}

void DisassemblerView::showListing()
{
    /*
    if(this->_disassembler->assembler()->hasVMIL())
    {
        ui->vmilTextView->setEmitMode(DisassemblerTextView::VMIL);
        ui->vmilTextView->setDisassembler(this->_disassembler);
        ui->topTabs->insertTab(VMIL_TAB_INDEX, ui->tabVMIL, "VMIL");
    }
    */

    ui->disassemblerMap->render(m_disassembler);
    ui->bottomTabs->setCurrentWidget(ui->tabStrings);
    ui->tbGoto->setEnabled(true);
    ui->leFunctionFilter->setEnabled(true);

    emit done();
}

void DisassemblerView::showHexDump(address_t address)
{
    ui->topTabs->setCurrentWidget(ui->hexEdit);

    offset_t offset = m_disassembler->format()->offset(address);
    QHexCursor* cursor = ui->hexEdit->document()->cursor();
    cursor->setSelectionRange(offset, 1);
}

void DisassemblerView::showMenu(const QPoint&)
{
    QAbstractItemView* view = dynamic_cast<QAbstractItemView*>(this->sender());

    if(!view)
        return;

    QItemSelectionModel* selectionmodel = view->selectionModel();

    if(!selectionmodel->hasSelection())
        return;

    this->_currentindex = selectionmodel->currentIndex();

    if(!this->_currentindex.isValid())
        return;

    m_contextmenu->exec(QCursor::pos());
}

void DisassemblerView::showGoto()
{
    GotoDialog dlggoto(m_disassembler, this);
    connect(&dlggoto, &GotoDialog::symbolSelected, this, &DisassemblerView::gotoSymbol);

    if(dlggoto.exec() == GotoDialog::Accepted)
        ui->disassemblerTextView->goTo(dlggoto.address());
}

void DisassemblerView::createMenu()
{
    m_contextmenu = new QMenu(this);
    m_contextmenu->addAction("Cross References", [this]() { this->xrefSymbol(this->_currentindex); });
    m_contextmenu->addAction("Goto", [this]() { this->gotoSymbol(this->_currentindex); });
}
