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

    m_importsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItem::SymbolItem, ui->tvFunctions);
    static_cast<SymbolTableModel*>(m_importsmodel->sourceModel())->setSymbolFlags(REDasm::SymbolTypes::ImportMask);
    ui->tvImports->setModel(m_importsmodel);

    m_exportsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItem::AllItems, ui->tvFunctions);
    static_cast<SymbolTableModel*>(m_exportsmodel->sourceModel())->setSymbolFlags(REDasm::SymbolTypes::ExportMask);
    ui->tvExports->setModel(m_exportsmodel);

    m_stringsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItem::SymbolItem, ui->tvStrings);
    static_cast<SymbolTableModel*>(m_stringsmodel->sourceModel())->setSymbolFlags(REDasm::SymbolTypes::StringMask);
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

    ui->tvReferences->setColumnHidden(0, true);
    ui->tvReferences->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->tvReferences->header()->setSectionResizeMode(2, QHeaderView::Stretch);

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
    connect(ui->disassemblerTextView, &DisassemblerTextView::addressChanged, this, &DisassemblerView::displayCurrentReferences);
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
    this->log(QString("Found format '%1' with '%2' instruction set").arg(S_TO_QS(disassembler->format()->name()),
                                                                         S_TO_QS(disassembler->assembler()->name())));

    REDasm::Buffer buffer = disassembler->format()->buffer();
    m_hexdocument = QHexDocument::fromMemory(reinterpret_cast<const char*>(buffer.data), buffer.length);
    m_hexdocument->setParent(this);

    m_functionsmodel->setDisassembler(disassembler);
    m_importsmodel->setDisassembler(disassembler);
    m_exportsmodel->setDisassembler(disassembler);
    m_stringsmodel->setDisassembler(disassembler);
    m_segmentsmodel->setDisassembler(disassembler);
    m_referencesmodel->setDisassembler(disassembler);

    ui->hexEdit->setDocument(m_hexdocument);
    ui->bottomTabs->setCurrentWidget(ui->tabOutput);
    ui->disassemblerTextView->setDisassembler(disassembler);
    //FIXME: ui->disassemblerGraphView->setDisassembler(disassembler);

    disassembler->finished += std::bind(&DisassemblerView::onDisassemblerFinished, this);
    disassembler->disassemble();
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

    if(w == ui->tabImports)
        ui->leFilter->setText(m_importsmodel->filter());
    else if(w == ui->tabExports)
        ui->leFilter->setText(m_exportsmodel->filter());
    else if(w == ui->tabStrings)
        ui->leFilter->setText(m_stringsmodel->filter());

    ui->leFilter->setEnabled(true);
}

void DisassemblerView::gotoXRef(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    ui->disassemblerTextView->goTo(static_cast<address_t>(index.internalId()));
}

void DisassemblerView::gotoSymbol(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(index.internalPointer());
    ui->disassemblerTextView->goTo(item);
}

void DisassemblerView::xrefSymbol(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    const ListingFilterModel* filtermodel = static_cast<const ListingFilterModel*>(index.model());
    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(filtermodel->mapToSource(index).internalPointer());
    REDasm::SymbolPtr symbol = m_disassembler->document()->symbol(item->address);

    if(!m_disassembler->getReferencesCount(item->address))
    {
        QMessageBox::information(this, "No References", "There are no references to " + S_TO_QS(symbol->name));
        return;
    }

    ReferencesDialog dlgreferences(m_disassembler, symbol, this);
    connect(&dlgreferences, &ReferencesDialog::jumpTo, [&](address_t address) { ui->disassemblerTextView->goTo(address); });
    dlgreferences.exec();
}

void DisassemblerView::displayAddress(address_t address)
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::FormatPlugin* format = doc->format();
    const REDasm::Segment* segment = doc->segment(address);

    QString segm = segment ? S_TO_QS(segment->name) : "???",
            offs = segment ? S_TO_QS(REDasm::hex(format->offset(address), format->bits(), false)) : "???",
            addr = S_TO_QS(REDasm::hex(address, format->bits(), false));

    QString s = QString("<b>Address: </b>%1\u00A0\u00A0<b>Offset: </b>%2\u00A0\u00A0<b>Segment: </b>%3").arg(addr, offs, segm);
    m_lblstatus->setText(s);
}

void DisassemblerView::displayCurrentReferences()
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    const std::string& word = doc->cursor()->wordUnderCursor();

    if(!word.empty())
    {
        REDasm::SymbolPtr symbol = doc->symbol(word);

        if(symbol)
        {
            m_referencesmodel->xref(symbol->address);
            return;
        }
    }

    REDasm::ListingItem* item = doc->itemAt(doc->cursor()->currentLine());
    m_referencesmodel->xref(item->address);
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

void DisassemblerView::log(const QString &s) { ui->pteOutput->insertPlainText(s + "\n"); }

void DisassemblerView::filterFunctions()
{
    QString s = ui->leFunctionFilter->text();

    if(s.length() == 1)
        return;

    m_functionsmodel->setFilter(s);
}

void DisassemblerView::filterSymbols()
{
    QString s = ui->leFilter->text();

    if(s.length() == 1)
        return;

    QWidget* w = ui->bottomTabs->currentWidget();

    if(w == ui->tabImports)
        m_importsmodel->setFilter(s);
    else if(w == ui->tabExports)
        m_exportsmodel->setFilter(s);
    else if(w == ui->tabStrings)
        m_stringsmodel->setFilter(s);
}

void DisassemblerView::onDisassemblerFinished()
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
