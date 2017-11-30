#include "disassemblerview.h"
#include "ui_disassemblerview.h"
#include "../../dialogs/referencesdialog.h"
#include <QMessageBox>

DisassemblerView::DisassemblerView(QLabel *lblstatus, QWidget *parent) : QWidget(parent), ui(new Ui::DisassemblerView), _hexdocument(NULL), _lblstatus(lblstatus), _disassembler(NULL), _disassemblerthread(NULL)
{
    ui->setupUi(this);
    ui->splitter->setStretchFactor(0, 1);

    ui->hexEdit->setReadOnly(true);
    ui->hexEdit->setFrameShape(QFrame::NoFrame);

    ui->tbBack->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Left));
    ui->tbForward->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Right));
    ui->tbGoto->setShortcut(QKeySequence(Qt::Key_G));

    this->_functionsmodel = new SymbolTableFilterModel(ui->tvFunctions);
    this->_functionsmodel->setFilterSymbol(REDasm::SymbolTypes::FunctionMask);
    ui->tvFunctions->setModel(this->_functionsmodel);

    this->_importsmodel = new SymbolTableFilterModel(ui->tvFunctions);
    this->_importsmodel->setFilterSymbol(REDasm::SymbolTypes::ImportMask);
    ui->tvImports->setModel(this->_importsmodel);

    this->_exportsmodel = new SymbolTableFilterModel(ui->tvFunctions);
    this->_exportsmodel->setFilterSymbol(REDasm::SymbolTypes::ExportMask);
    ui->tvExports->setModel(this->_exportsmodel);

    this->_stringsmodel = new SymbolTableFilterModel(ui->tvStrings);
    this->_stringsmodel->setFilterSymbol(REDasm::SymbolTypes::StringMask);
    ui->tvStrings->setModel(this->_stringsmodel);

    this->_segmentsmodel = new SegmentsModel(ui->tvSegments);
    ui->tvSegments->setModel(this->_segmentsmodel);

    ui->tvFunctions->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvImports->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvExports->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvStrings->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    ui->tvSegments->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    ui->tvFunctions->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvImports->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvExports->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvStrings->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

    connect(ui->disassemblerTextView, &DisassemblerTextView::addressChanged, this, &DisassemblerView::displayAddress);
    connect(ui->disassemblerTextView, &DisassemblerTextView::gotoRequested, this, &DisassemblerView::showGoto);
    connect(ui->disassemblerTextView, &DisassemblerTextView::hexDumpRequested, this, &DisassemblerView::showHexDump);
    connect(ui->disassemblerTextView, &DisassemblerTextView::symbolRenamed, this, &DisassemblerView::updateModel);
    connect(ui->disassemblerTextView, &DisassemblerTextView::invalidateSymbols, [this]() { this->updateModel(NULL);});
    connect(ui->disassemblerTextView, &DisassemblerTextView::canGoBackChanged, [this]() { ui->tbBack->setEnabled(ui->disassemblerTextView->canGoBack()); });
    connect(ui->disassemblerTextView, &DisassemblerTextView::canGoForwardChanged, [this]() { ui->tbForward->setEnabled(ui->disassemblerTextView->canGoForward()); });

    connect(ui->tbBack, &QToolButton::clicked, ui->disassemblerTextView, &DisassemblerTextView::goBack);
    connect(ui->tbForward, &QToolButton::clicked, ui->disassemblerTextView, &DisassemblerTextView::goForward);
    connect(ui->tbGoto, &QToolButton::clicked, this, &DisassemblerView::showGoto);

    connect(ui->tvFunctions, &QTableView::doubleClicked, this, &DisassemblerView::seekToSymbol);
    connect(ui->tvExports, &QTableView::doubleClicked, this, &DisassemblerView::seekToSymbol);
    connect(ui->tvImports, &QTableView::doubleClicked, this, &DisassemblerView::xrefSymbol);
    connect(ui->tvStrings, &QTableView::doubleClicked, this, &DisassemblerView::xrefSymbol);

    connect(ui->leFilter, &QLineEdit::textChanged, [this](const QString&) { this->filterSymbols(); });
}

DisassemblerView::~DisassemblerView()
{
    delete ui;

    if(this->_disassembler)
        delete this->_disassembler;
}

void DisassemblerView::setDisassembler(REDasm::Disassembler *disassembler)
{
    this->_disassembler = disassembler;
    this->log(QString("Found format '%1'").arg(S_TO_QS(disassembler->format()->name())));

    disassembler->loggerCallback([this](std::string s) {
        QMetaObject::invokeMethod(this, "log", Qt::QueuedConnection, Q_ARG(QString, S_TO_QS(s)));
    });

    REDasm::Buffer& buffer = disassembler->buffer();
    this->_hexdocument = QHexDocument::fromMemory(reinterpret_cast<const char*>(buffer.data), buffer.length);
    this->_hexdocument->setParent(this);

    ui->hexEdit->setDocument(this->_hexdocument);
    ui->tabWidget->setCurrentWidget(ui->tabOutput);

    this->_disassemblerthread = new DisassemblerThread(disassembler, this);

    connect(this->_disassemblerthread, &DisassemblerThread::finished, this, &DisassemblerView::showListing);

    connect(this->_disassemblerthread, &DisassemblerThread::finished, [this]() {
        this->_disassemblerthread->deleteLater();
        this->_disassemblerthread = NULL;
    });

    this->_disassemblerthread->start();
}

bool DisassemblerView::busy() const
{
    if(!this->_disassemblerthread)
        return false;

    return this->_disassemblerthread->isRunning();
}

void DisassemblerView::on_tabWidget_currentChanged(int index)
{
    QWidget* w = ui->tabWidget->widget(index);

    if(!w || ((w == ui->tabSegments) || (w == ui->tabOutput) || (w == ui->hexEdit)))
    {
        ui->leFilter->setEnabled(false);
        ui->leFilter->clear();
        return;
    }

    if(w == ui->tabFunctions)
        ui->leFilter->setText(this->_functionsmodel->filterName());
    else if(w == ui->tabImports)
        ui->leFilter->setText(this->_importsmodel->filterName());
    else if(w == ui->tabExports)
        ui->leFilter->setText(this->_exportsmodel->filterName());
    else if(w == ui->tabStrings)
        ui->leFilter->setText(this->_stringsmodel->filterName());

    ui->leFilter->setEnabled(true);
}

void DisassemblerView::seekToSymbol(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    const SymbolTableFilterModel* filtermodel = static_cast<const SymbolTableFilterModel*>(index.model());
    QModelIndex srcindex = filtermodel->mapToSource(index);
    REDasm::Symbol* symbol = reinterpret_cast<REDasm::Symbol*>(srcindex.internalPointer());

    const REDasm::Segment* segment = this->_disassembler->format()->segment(symbol->address);

    if(!segment)
        return;
    else if(segment->is(REDasm::SegmentTypes::Code))
        ui->disassemblerTextView->goTo(symbol);
    else
        this->xrefSymbol(index);
}

void DisassemblerView::xrefSymbol(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    const SymbolTableFilterModel* filtermodel = static_cast<const SymbolTableFilterModel*>(index.model());
    QModelIndex srcindex = filtermodel->mapToSource(index);
    REDasm::Symbol* symbol = reinterpret_cast<REDasm::Symbol*>(srcindex.internalPointer());

    if(!this->_disassembler->hasReferences(symbol))
    {
        QMessageBox::information(this, "No References", "There are no references to " + S_TO_QS(symbol->name));
        return;
    }

    ReferencesDialog dlgreferences(this->_disassembler, ui->disassemblerTextView->currentAddress(), symbol, this);
    connect(&dlgreferences, &ReferencesDialog::jumpTo, [this](address_t address) { ui->disassemblerTextView->goTo(address); });
    dlgreferences.exec();
}

void DisassemblerView::displayAddress(address_t address)
{
    int bits = this->_disassembler->format()->bits();
    offset_t offset = this->_disassembler->format()->offset(address);
    const REDasm::Segment* segment = this->_disassembler->format()->segment(address);

    QString s = QString("<b>%1:%2</b>\u00A0\u00A0[%3]\u00A0\u00A0\u00A0\u00A0").arg(segment ? S_TO_QS(segment->name) : "unk",
                                                                                    S_TO_QS(REDasm::hex(address, bits, false)),
                                                                                    S_TO_QS(REDasm::hex(offset, bits, false)));

    this->_lblstatus->setText(s);
}

void DisassemblerView::updateModel(const REDasm::Symbol *symbol)
{
    if(!symbol)
    {
        this->_functionsmodel->invalidate();
        this->_stringsmodel->invalidate();
        return;
    }

    if(symbol->isFunction())
    {
        this->_functionsmodel->invalidate();
        this->_exportsmodel->invalidate();
    }
    else if(symbol->is(REDasm::SymbolTypes::ImportMask))
        this->_importsmodel->invalidate();
    else if(symbol->is(REDasm::SymbolTypes::String))
        this->_stringsmodel->invalidate();
}

void DisassemblerView::log(const QString &s)
{
    ui->pteOutput->insertPlainText(s + "\n");
}

void DisassemblerView::filterSymbols()
{
    QString s = ui->leFilter->text();

    if(s.length() == 1)
        return;

    QWidget* w = ui->tabWidget->currentWidget();

    if(w == ui->tabFunctions)
        this->_functionsmodel->setFilterName(s);
    else if(w == ui->tabImports)
        this->_importsmodel->setFilterName(s);
    else if(w == ui->tabExports)
        this->_exportsmodel->setFilterName(s);
    else if(w == ui->tabStrings)
        this->_stringsmodel->setFilterName(s);
}

void DisassemblerView::showListing()
{
    ui->disassemblerTextView->setDisassembler(this->_disassembler);
    ui->disassemblerMap->render(this->_disassembler);

    this->_functionsmodel->setDisassembler(this->_disassembler);
    this->_importsmodel->setDisassembler(this->_disassembler);
    this->_exportsmodel->setDisassembler(this->_disassembler);
    this->_stringsmodel->setDisassembler(this->_disassembler);
    this->_segmentsmodel->setDisassembler(this->_disassembler);

    ui->tabWidget->setCurrentWidget(ui->tabFunctions);
    ui->tbGoto->setEnabled(true);
    emit done();
}

void DisassemblerView::showHexDump(address_t address)
{
    ui->tabWidget->setCurrentWidget(ui->hexEdit);

    offset_t offset = this->_disassembler->format()->offset(address);
    QHexCursor* cursor = ui->hexEdit->document()->cursor();
    cursor->setSelectionRange(offset, 1);
}

void DisassemblerView::showGoto()
{
    GotoDialog dlggoto(this->_disassembler, this);
    connect(&dlggoto, &GotoDialog::symbolSelected, this, &DisassemblerView::seekToSymbol);

    if(dlggoto.exec() == GotoDialog::Accepted)
        ui->disassemblerTextView->goTo(dlggoto.address());
}
