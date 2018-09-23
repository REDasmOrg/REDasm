#include "disassemblerview.h"
#include "ui_disassemblerview.h"
#include "../../dialogs/referencesdialog.h"
#include <QMessageBox>
#include <QPushButton>

DisassemblerView::DisassemblerView(QLabel *lblstatus, QPushButton *pbstatus, QWidget *parent) : QWidget(parent), ui(new Ui::DisassemblerView), m_hexdocument(NULL), m_lblstatus(lblstatus), m_pbstatus(pbstatus), m_disassembler(NULL)
{
    ui->setupUi(this);
    ui->leFilter->setVisible(false);

    ui->vSplitter->setSizes((QList<int>() << this->width() * 0.70
                                          << this->width() * 0.30));

    ui->vSplitter2->setSizes((QList<int>() << this->width() * 0.70
                                           << this->width() * 0.30));

    ui->hSplitter->setSizes((QList<int>() << this->width() * 0.30
                                          << this->width() * 0.70));

    m_disassemblertextview = new DisassemblerTextView(ui->stackedWidget);
    m_disassemblergraphview = new DisassemblerGraphView(ui->stackedWidget);

    ui->hexEdit->setReadOnly(true);
    ui->hexEdit->setFrameShape(QFrame::NoFrame);

    ui->stackedWidget->addWidget(m_disassemblertextview);
    ui->stackedWidget->addWidget(m_disassemblergraphview);

    ui->tbBack->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Left));
    ui->tbForward->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Right));
    ui->tbGoto->setShortcut(QKeySequence(Qt::Key_G));

    m_functionsmodel = ListingFilterModel::createFilter<ListingItemModel>(REDasm::ListingItem::FunctionItem, ui->tvFunctions);
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

    m_callgraphmodel = new CallGraphModel(ui->tvCallGraph);
    ui->tvCallGraph->setModel(m_callgraphmodel);

    m_referencesmodel = new ReferencesModel(ui->tvReferences);
    ui->tvReferences->setModel(m_referencesmodel);

    ui->leFilter->installEventFilter(this);

    ui->tvFunctions->setColumnHidden(3, true);
    ui->tvFunctions->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvFunctions->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvFunctions->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->tvFunctions->header()->moveSection(2, 1);

    ui->tvCallGraph->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvCallGraph->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvCallGraph->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);

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

    connect(ui->bottomTabs, &QTabWidget::currentChanged, this, &DisassemblerView::updateCurrentFilter);
    connect(ui->leFilter, &QLineEdit::textChanged, [&](const QString&) { this->filterSymbols(); });
    connect(m_pbstatus, &QPushButton::clicked, this, &DisassemblerView::changeDisassemblerStatus);

    connect(m_disassemblertextview, &DisassemblerTextView::gotoRequested, this, &DisassemblerView::showGoto);
    connect(m_disassemblertextview, &DisassemblerTextView::hexDumpRequested, this, &DisassemblerView::showHexDump);
    connect(m_disassemblertextview, &DisassemblerTextView::callGraphRequested, this, &DisassemblerView::initializeCallGraph);
    connect(m_disassemblertextview, &DisassemblerTextView::addressChanged, this, &DisassemblerView::displayAddress);
    connect(m_disassemblertextview, &DisassemblerTextView::addressChanged, this, &DisassemblerView::displayCurrentReferences);
    connect(m_disassemblertextview, &DisassemblerTextView::canGoBackChanged, [=]() { ui->tbBack->setEnabled(m_disassemblertextview->canGoBack()); });
    connect(m_disassemblertextview, &DisassemblerTextView::canGoForwardChanged, [=]() { ui->tbForward->setEnabled(m_disassemblertextview->canGoForward()); });

    connect(ui->tbBack, &QToolButton::clicked, m_disassemblertextview, &DisassemblerTextView::goBack);
    connect(ui->tbForward, &QToolButton::clicked, m_disassemblertextview, &DisassemblerTextView::goForward);
    connect(ui->tbGoto, &QToolButton::clicked, this, &DisassemblerView::showGoto);

    connect(ui->tvReferences, &QTreeView::doubleClicked, this, &DisassemblerView::gotoXRef);
    connect(ui->tvCallGraph, &QTreeView::expanded, m_callgraphmodel, &CallGraphModel::populateCallGraph);
    connect(ui->tvCallGraph, &QTreeView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(ui->tvCallGraph, &QTreeView::doubleClicked, this, &DisassemblerView::goTo);
    connect(ui->tvCallGraph, &QTreeView::customContextMenuRequested, this, &DisassemblerView::showMenu);
    connect(ui->tvFunctions, &QTableView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(ui->tvFunctions, &QTreeView::doubleClicked, this, &DisassemblerView::goTo);
    connect(ui->tvFunctions, &QTreeView::customContextMenuRequested, this, &DisassemblerView::showMenu);
    connect(ui->tvExports, &QTableView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(ui->tvExports, &QTableView::doubleClicked, this, &DisassemblerView::goTo);
    connect(ui->tvExports, &QTableView::customContextMenuRequested, this, &DisassemblerView::showMenu);
    connect(ui->tvImports, &QTableView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(ui->tvImports, &QTableView::doubleClicked, this, &DisassemblerView::goTo);
    connect(ui->tvImports, &QTableView::customContextMenuRequested, this, &DisassemblerView::showMenu);
    connect(ui->tvStrings, &QTableView::pressed, this, &DisassemblerView::modelIndexSelected);
    connect(ui->tvStrings, &QTableView::doubleClicked, this, &DisassemblerView::goTo);
    connect(ui->tvStrings, &QTableView::customContextMenuRequested, this, &DisassemblerView::showMenu);

    REDasm::setLoggerCallback([this](const std::string& s) {
        QMetaObject::invokeMethod(this, "log", Qt::QueuedConnection, Q_ARG(QString, S_TO_QS(s)));
    });

    this->createActions();
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
    m_callgraphmodel->setDisassembler(disassembler);
    m_referencesmodel->setDisassembler(disassembler);

    ui->hexEdit->setDocument(m_hexdocument);
    ui->bottomTabs->setCurrentWidget(ui->tabOutput);
    ui->disassemblerMap->setDisassembler(disassembler);
    m_disassemblertextview->setDisassembler(disassembler);
    m_disassemblergraphview->setDisassembler(disassembler);

    disassembler->busyChanged += std::bind(&DisassemblerView::checkDisassemblerStatus, this);
    disassembler->disassemble();
}

void DisassemblerView::changeDisassemblerStatus()
{
    if(m_disassembler->state() == REDasm::Timer::ActiveState)
        m_disassembler->pause();
    else if(m_disassembler->state() == REDasm::Timer::PausedState)
        m_disassembler->resume();
}

void DisassemblerView::checkDisassemblerStatus()
{
    size_t state = m_disassembler->state();

    if(state == REDasm::Timer::ActiveState)
        m_pbstatus->setStyleSheet("color: red;");
    else if(state == REDasm::Timer::PausedState)
        m_pbstatus->setStyleSheet("color: goldenrod;");
    else
        m_pbstatus->setStyleSheet("color: green;");

    m_pbstatus->setVisible(true);
    m_actsetfilter->setEnabled(!m_disassembler->busy());
    ui->tbGoto->setEnabled(!m_disassembler->busy());
    ui->tbListingGraph->setEnabled(!m_disassembler->busy());
    ui->leFilter->setEnabled(!m_disassembler->busy());
}

void DisassemblerView::modelIndexSelected(const QModelIndex &index)
{
    m_currentindex = index;
    m_actsetfilter->setVisible(index.isValid() && (index.model() != m_callgraphmodel));
}

void DisassemblerView::updateCurrentFilter(int index)
{
    QWidget* w = ui->bottomTabs->widget(index);

    if(!w)
        return;

    if(w == ui->tabSegments)
        m_segmentsmodel->setFilter(ui->leFilter->text());
    else if(w == ui->tabImports)
        m_importsmodel->setFilter(ui->leFilter->text());
    else if(w == ui->tabExports)
        m_exportsmodel->setFilter(ui->leFilter->text());
    else if(w == ui->tabStrings)
        m_stringsmodel->setFilter(ui->leFilter->text());
}

void DisassemblerView::gotoXRef(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    m_disassemblertextview->goTo(static_cast<address_t>(index.internalId()));
}

void DisassemblerView::goTo(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(index.internalPointer());
    m_disassemblertextview->goTo(item);
}

void DisassemblerView::showReferences()
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

    if(!m_disassembler->getReferencesCount(symbol->address))
    {
        QMessageBox::information(this, "No References", "There are no references to " + S_TO_QS(symbol->name));
        return;
    }

    ReferencesDialog dlgreferences(m_disassembler, symbol, this);
    connect(&dlgreferences, &ReferencesDialog::jumpTo, [&](address_t address) { m_disassemblertextview->goTo(address); });
    dlgreferences.exec();
}

void DisassemblerView::displayAddress(address_t address)
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::FormatPlugin* format = doc->format();
    const REDasm::Segment* segment = doc->segment(address);
    REDasm::SymbolPtr functionstart = doc->functionStartSymbol(address);

    QString segm = segment ? S_TO_QS(segment->name) : "???",
            offs = segment ? S_TO_QS(REDasm::hex(format->offset(address), format->bits(), false)) : "???",
            addr = S_TO_QS(REDasm::hex(address, format->bits(), false));

    QString s = QString("<b>Address: </b>%1\u00A0\u00A0").arg(addr);
    s += QString("<b>Offset: </b>%1\u00A0\u00A0").arg(offs);
    s += QString("<b>Segment: </b>%1\u00A0\u00A0").arg(segm);

    REDasm::ListingItem* item = doc->currentItem();

    if(item && item->is(REDasm::ListingItem::InstructionItem))
    {
        QString func = "???";

        if(functionstart)
        {
            func = S_TO_QS(functionstart->name);
            size_t offset = address - functionstart->address;

            if(offset)
                func += "+" + S_TO_QS(REDasm::hex(offset, 8, false));
        }

        s = QString("<b>Function: </b>%1\u00A0\u00A0").arg(func) + s;
    }

    m_lblstatus->setText(s);
}

void DisassemblerView::initializeCallGraph(address_t address)
{
    m_callgraphmodel->initializeGraph(address);
    ui->tvCallGraph->expandToDepth(0);
    ui->tabModels->setCurrentIndex(1);
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

void DisassemblerView::log(const QString &s) { ui->pteOutput->insertPlainText(s + "\n"); }

void DisassemblerView::filterSymbols()
{
    if(!m_currentindex.isValid())
        return;

    ListingFilterModel* filtermodel = this->getSelectedFilterModel();

    if(!filtermodel)
        return;

    filtermodel->setFilter(ui->leFilter->text());
}

void DisassemblerView::showFilter()
{
    ListingFilterModel* filtermodel = this->getSelectedFilterModel();

    if(!filtermodel)
        return;

    ui->leFilter->show();
    ui->leFilter->setFocus();
}

void DisassemblerView::clearFilter()
{
    ui->leFilter->clear();
    ui->leFilter->hide();

    m_functionsmodel->clearFilter();
    m_segmentsmodel->clearFilter();
    m_importsmodel->clearFilter();
    m_exportsmodel->clearFilter();
    m_stringsmodel->clearFilter();
}

void DisassemblerView::showHexDump(address_t address)
{
    ui->bottomTabs->setCurrentWidget(ui->hexEdit);

    offset_t offset = m_disassembler->format()->offset(address);
    QHexCursor* cursor = ui->hexEdit->document()->cursor();
    cursor->setSelectionRange(offset, 1);
}

void DisassemblerView::showMenu(const QPoint&) { m_contextmenu->exec(QCursor::pos()); }

void DisassemblerView::showGoto()
{
    GotoDialog dlggoto(m_disassembler, this);
    connect(&dlggoto, &GotoDialog::symbolSelected, this, &DisassemblerView::goTo);

    if(dlggoto.exec() == GotoDialog::Accepted)
        m_disassemblertextview->goTo(dlggoto.address());
}

bool DisassemblerView::eventFilter(QObject *obj, QEvent *e)
{
    if((obj == ui->leFilter) && (e->type() == QEvent::KeyPress))
    {
        QKeyEvent* keyevent = static_cast<QKeyEvent*>(e);

        if(keyevent->matches(QKeySequence::Cancel))
        {
            this->clearFilter();
            return true;
        }
    }

    return QWidget::eventFilter(obj, e);
}

void DisassemblerView::createActions()
{
    m_contextmenu = new QMenu(this);
    m_actsetfilter = m_contextmenu->addAction("Set Filter", this, &DisassemblerView::showFilter, Qt::Key_F3);
    this->addAction(m_actsetfilter);

    m_contextmenu->addSeparator();
    m_contextmenu->addAction("Cross References", this, &DisassemblerView::showReferences);
    m_contextmenu->addAction("Goto", [&]() { this->goTo(m_currentindex); });
}

ListingFilterModel *DisassemblerView::getSelectedFilterModel()
{
    if(!m_currentindex.isValid())
        return NULL;

    const ListingFilterModel* model = dynamic_cast<const ListingFilterModel*>(m_currentindex.model());

    if(!model)
        return NULL;

    if(model == m_functionsmodel)
        return m_functionsmodel;
    else if(model == m_segmentsmodel)
        return m_segmentsmodel;
    else if(model == m_importsmodel)
        return m_importsmodel;
    else if(model == m_exportsmodel)
        return m_exportsmodel;
    else if(model == m_stringsmodel)
        return m_stringsmodel;

    return NULL;
}
