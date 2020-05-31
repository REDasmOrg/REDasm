#include "disassemblerhooks.h"
#include "../dialogs/tabledialog/tabledialog.h"
#include "../dialogs/aboutdialog/aboutdialog.h"
#include "../dialogs/settingsdialog/settingsdialog.h"
#include "../dialogs/loaderdialog/loaderdialog.h"
#include "../dialogs/referencesdialog/referencesdialog.h"
#include "../dialogs/gotodialog/gotodialog.h"
#include "../dialogs/dev/iteminformationdialog/iteminformationdialog.h"
#include "../dialogs/dev/functiongraphdialog/functiongraphdialog.h"
#include "../widgets/tabs/welcometab/welcometab.h"
#include "../widgets/docks/outputdock/outputdock.h"
#include "../widgets/tabs/tabletab/tabletab.h"
#include "../widgets/disassemblerview.h"
#include "../models/dev/blocklistmodel.h"
#include "../models/listingitemmodel.h"
#include "../models/symboltablemodel.h"
#include "../models/segmentsmodel.h"
#include "../redasmsettings.h"
#include "../redasmfonts.h"
#include <QMessageBox>
#include <QApplication>
#include <QInputDialog>
#include <QMessageBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QToolBar>
#include <QMenuBar>
#include <QMenu>
#include <unordered_map>
#include <rdapi/rdapi.h>

DisassemblerHooks DisassemblerHooks::m_instance;

DisassemblerHooks::DisassemblerHooks(QObject* parent): QObject(parent) { }

DisassemblerHooks::~DisassemblerHooks()
{
    if(m_worker.valid()) m_worker.get();
    RDEvent_Unsubscribe(this);
}

void DisassemblerHooks::initialize(QMainWindow* mainwindow)
{
    DisassemblerHooks::m_instance.m_mainwindow = mainwindow;
    DisassemblerHooks::m_instance.hook();
}

DisassemblerHooks* DisassemblerHooks::instance() { return &m_instance; }
void DisassemblerHooks::log(const QString& s) { this->outputDock()->log(s); }
void DisassemblerHooks::clearLog() { this->outputDock()->clear(); }

void DisassemblerHooks::resetLayout()
{

}

void DisassemblerHooks::open()
{
    QString s = QFileDialog::getOpenFileName(m_mainwindow, "Disassemble file...");
    if(!s.isEmpty()) this->load(s);
}

void DisassemblerHooks::close() { this->close(true); }

void DisassemblerHooks::save()
{

}

void DisassemblerHooks::saveAs()
{

}

void DisassemblerHooks::settings()
{
    SettingsDialog dlgsettings(m_mainwindow);
    dlgsettings.exec();
}

void DisassemblerHooks::about()
{
    AboutDialog dlgabout(m_mainwindow);
    dlgabout.exec();
}

void DisassemblerHooks::exit() { qApp->exit(); }

ITableTab* DisassemblerHooks::showSegments(Qt::DockWidgetArea area)
{
    if(auto* t = this->findModelInTabs<SegmentsModel>())
    {
        this->focusOn(dynamic_cast<QWidget*>(t));
        return t;
    }

    TableTab* tabletab = this->createTable(new SegmentsModel(), "Segments");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

ITableTab* DisassemblerHooks::showFunctions(Qt::DockWidgetArea area)
{
    if(auto* t = this->findModelInTabs<ListingItemModel>())
    {
        if(t->model()->itemType() == DocumentItemType_Function)
        {
            this->focusOn(dynamic_cast<QWidget*>(t));
            return t;
        }
    }

    TableTab* tabletab = this->createTable(new ListingItemModel(DocumentItemType_Function), "Functions");
    tabletab->setColumnHidden(1);
    tabletab->setColumnHidden(2);
    connect(tabletab, &TableTab::resizeColumns, this, [tabletab]() { tabletab->resizeColumn(0); });

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

ITableTab* DisassemblerHooks::showExports(Qt::DockWidgetArea area)
{
    if(auto* t = this->findSymbolModelInTabs(SymbolType_Function, SymbolFlags_Export))
    {
        this->focusOn(dynamic_cast<QWidget*>(t));
        return t;
    }

    auto* model = new SymbolTableModel(DocumentItemType_All);
    model->setSymbolType(SymbolType_Function);
    model->setSymbolFlags(SymbolFlags_Export);

    TableTab* tabletab = this->createTable(model, "Exports");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

ITableTab* DisassemblerHooks::showImports(Qt::DockWidgetArea area)
{
    if(auto* t = this->findSymbolModelInTabs(SymbolType_Import, SymbolFlags_None))
    {
        this->focusOn(dynamic_cast<QWidget*>(t));
        return t;
    }

    auto* model = new SymbolTableModel(DocumentItemType_Symbol);
    model->setSymbolType(SymbolType_Import);

    TableTab* tabletab = this->createTable(model, "Imports");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

ITableTab* DisassemblerHooks::showStrings(Qt::DockWidgetArea area)
{
    if(auto* t = this->findSymbolModelInTabs(SymbolType_String, SymbolFlags_None))
    {
        this->focusOn(dynamic_cast<QWidget*>(t));
        return t;
    }

    auto* model = new SymbolTableModel(DocumentItemType_Symbol);
    model->setSymbolType(SymbolType_String);

    TableTab* tabletab = this->createTable(model, "Strings");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

void DisassemblerHooks::showReferences(IDisassemblerCommand* command, address_t address)
{
    RDDocument* doc = RDDisassembler_GetDocument(command->disassembler());

    RDSymbol symbol;
    if(!RDDocument_GetSymbolByAddress(doc, address, &symbol)) return;

    if(!RDDisassembler_GetReferencesCount(command->disassembler(), symbol.address))
    {
        QMessageBox::information(nullptr, "No References", QString("There are no references to %1 ").arg(RDDocument_GetSymbolName(doc, symbol.address)));
        return;
    }

    ReferencesDialog dlgreferences(command, &symbol, m_mainwindow);
    dlgreferences.exec();
}

void DisassemblerHooks::showGoto(IDisassemblerCommand* command)
{
    GotoDialog dlggoto(command);
    dlggoto.exec();
}

void DisassemblerHooks::showDevGraphs()
{
    if(!m_disassemblerview) return;

    static FunctionGraphDialog* dlgfuncgraph = nullptr;
    if(!dlgfuncgraph) dlgfuncgraph = new FunctionGraphDialog(m_mainwindow);

    dlgfuncgraph->setDisassembler(m_disassemblerview->disassembler());
    dlgfuncgraph->show();
}

void DisassemblerHooks::showDevBlocks()
{
    if(!m_disassemblerview) return;

    static TableDialog* td = nullptr;

    if(!td)
    {
        td = new TableDialog(m_mainwindow);
        td->setWindowTitle("Block List");
        td->enableFiltering();
        td->setButtonBoxVisible(false);
    }

    RDDisassembler* disassembler = m_disassemblerview->disassembler();
    td->setModel(new BlockListModel(RDDisassembler_GetDocument(disassembler)));
    td->show();
}

ICommandTab* DisassemblerHooks::activeCommandTab() const
{
    if(!m_activecommandtab) m_activecommandtab = m_disassemblerview->showListing();
    return m_activecommandtab;
}

IDisassemblerCommand* DisassemblerHooks::activeCommand() const { return this->activeCommandTab()->command(); }
QWidget* DisassemblerHooks::currentTab() const { return m_disassemblertabs->currentWidget(); }

void DisassemblerHooks::undock(QDockWidget* dw)
{
    m_mainwindow->removeDockWidget(dw);

    if(auto* d = dynamic_cast<IDisposable*>(dw)) d->dispose();
    else dw->deleteLater();
}

void DisassemblerHooks::onToolBarActionTriggered(QAction* action)
{
    if(!m_activecommandtab) return;

    int idx = m_toolbar->actions().indexOf(action);

    switch(idx)
    {
        case 2: m_activecommandtab->command()->goBack(); break;
        case 3: m_activecommandtab->command()->goForward(); break;
        case 4: this->showGoto(m_activecommandtab->command()); break;

        case 5: {
            auto* tabletab = dynamic_cast<ITableTab*>(m_disassemblertabs->currentWidget());
            if(tabletab) tabletab->toggleFilter();
            break;
        }

        default: break;
    }
}

void DisassemblerHooks::onWindowActionTriggered(QAction* action)
{
    int idx = m_mnuwindow->actions().indexOf(action);

    switch(idx)
    {
        case 0: {
            ICommandTab* tab = m_activecommandtab;
            if(!tab) tab = m_disassemblerview->showListing();
            this->focusOn(dynamic_cast<QWidget*>(tab));
            break;
        }

        case 1: this->showSegments();  break;
        case 2: this->showFunctions(); break;
        case 3: this->showExports();   break;
        case 4: this->showImports();   break;
        case 5: this->showStrings();   break;
        default: break;
    }
}

void DisassemblerHooks::statusAddress(const IDisassemblerCommand* command) const
{
    if(RD_IsBusy()) return;

    RDDocument* doc = RDDisassembler_GetDocument(command->disassembler());

    RDDocumentItem item;
    if(!command->getCurrentItem(&item)) return;

    RDLoader* ldr = RDDisassembler_GetLoader(command->disassembler());

    RDSegment segment;
    bool hassegment = RDDocument_GetSegmentAddress(doc, item.address, &segment);

    RDLocation functionstart = RDDocument_FunctionStart(doc, item.address);
    RDLocation offset = RD_Offset(ldr, item.address);

    QString segm = hassegment ? segment.name : "UNKNOWN",
            offs = hassegment && offset.valid ? RD_ToHexAuto(offset.value) : "UNKNOWN",
            addr = RD_ToHexAuto(item.address);

    QString s = QString::fromWCharArray(L"<b>Address: </b>%1\u00A0\u00A0").arg(addr);
    s += QString::fromWCharArray(L"<b>Offset: </b>%1\u00A0\u00A0").arg(offs);
    s += QString::fromWCharArray(L"<b>Segment: </b>%1\u00A0\u00A0").arg(segm);

    const char* functionstartname = RDDocument_GetSymbolName(doc, functionstart.value);

    if(functionstart.valid && functionstartname)
    {
        QString func = functionstartname;

        if(item.address > functionstart.value)
            func += "+" + QString::fromUtf8(RD_ToHexBits(item.address - functionstart.value, 8, false));
        else if(item.address < functionstart.value)
            func += QString::number(static_cast<std::make_signed<size_t>::type>(item.address - functionstart.value));

        s = QString::fromWCharArray(L"<b>Function: </b>%1\u00A0\u00A0").arg(func) + s;
    }

    RD_Status(qUtf8Printable(s));
}

void DisassemblerHooks::adjustActions()
{
    QMenu* menu = static_cast<QMenu*>(this->sender());
    std::unordered_map<int, QAction*> actions;

    for(QAction* action : menu->actions())
    {
        QVariant data = action->data();
        if(!data.isNull()) actions[data.toInt()] = action;
    }

    IDisassemblerCommand* command = dynamic_cast<IDisassemblerCommand*>(menu->parentWidget());
    RDDocumentItem item;
    if(!command->getCurrentItem(&item)) return;

    actions[DisassemblerHooks::Action_Back]->setVisible(command->canGoBack());
    actions[DisassemblerHooks::Action_Forward]->setVisible(command->canGoForward());
    actions[DisassemblerHooks::Action_Copy]->setVisible(command->hasSelection());
    actions[DisassemblerHooks::Action_Goto]->setVisible(!RD_IsBusy());
    actions[DisassemblerHooks::Action_ItemInformation]->setVisible(!RD_IsBusy());

    RDDocument* doc = RDDisassembler_GetDocument(command->disassembler());
    RDSegment itemsegment, symbolsegment;
    RDSymbol symbol;

    if(!command->getSelectedSymbol(&symbol))
    {
        bool hassymbolsegment = RDDocument_GetSegmentAddress(doc, item.address, &symbolsegment);
        RDLocation funcstart = RDDocument_FunctionStart(doc, item.address);
        const char* funcname = funcstart.valid ? RDDocument_GetSymbolName(doc, funcstart.value) : nullptr;

        actions[DisassemblerHooks::Action_Rename]->setVisible(false);
        actions[DisassemblerHooks::Action_XRefs]->setVisible(false);
        actions[DisassemblerHooks::Action_Follow]->setVisible(false);
        actions[DisassemblerHooks::Action_FollowPointerHexDump]->setVisible(false);

        if(!RD_IsBusy())
        {
            bool ok = false;
            RDSegment currentsegment;
            address_t currentaddress = command->currentWord().toUInt(&ok, 16);
            bool hascurrentsegment = ok ? RDDocument_GetSegmentAddress(doc, currentaddress, &currentsegment) : false;

            actions[DisassemblerHooks::Action_CreateFunction]->setVisible(hascurrentsegment && HAS_FLAG(&currentsegment, SegmentFlags_Code));

            if(hascurrentsegment)
                actions[DisassemblerHooks::Action_CreateFunction]->setText(QString("Create Function @ %1").arg(RD_ToHexAuto(currentaddress)));
        }
        else
            actions[DisassemblerHooks::Action_CreateFunction]->setVisible(false);

        if(funcname)
            actions[DisassemblerHooks::Action_CallGraph]->setText(QString("Callgraph %1").arg(funcname));

        actions[DisassemblerHooks::Action_CallGraph]->setVisible(funcname && hassymbolsegment && HAS_FLAG(&symbolsegment, SegmentFlags_Code));
        actions[DisassemblerHooks::Action_HexDumpFunction]->setVisible(funcname);
        actions[DisassemblerHooks::Action_HexDump]->setVisible(true);
        return;
    }

    bool hasitemsegment = RDDocument_GetSegmentAddress(doc, item.address, &itemsegment);
    const char* symbolname = RDDocument_GetSymbolName(doc, symbol.address);
    bool hassymbolsegment = RDDocument_GetSegmentAddress(doc, symbol.address, &symbolsegment);

    actions[DisassemblerHooks::Action_CreateFunction]->setText(QString("Create Function @ %1").arg(RD_ToHexAuto(symbol.address)));

    actions[DisassemblerHooks::Action_CreateFunction]->setVisible(!RD_IsBusy() && (hassymbolsegment && HAS_FLAG(&symbolsegment,SegmentFlags_Code)) &&
                                                                    (HAS_FLAG(&symbol, SymbolFlags_Weak) && !IS_TYPE(&symbol, SymbolType_Function)));


    actions[DisassemblerHooks::Action_FollowPointerHexDump]->setText(QString("Follow %1 pointer in Hex Dump").arg(symbolname));
    actions[DisassemblerHooks::Action_FollowPointerHexDump]->setVisible(HAS_FLAG(&symbol, SymbolFlags_Pointer));

    actions[DisassemblerHooks::Action_XRefs]->setText(QString("Cross Reference %1").arg(symbolname));
    actions[DisassemblerHooks::Action_XRefs]->setVisible(!RD_IsBusy());

    actions[DisassemblerHooks::Action_Rename]->setText(QString("Rename %1").arg(symbolname));
    actions[DisassemblerHooks::Action_Rename]->setVisible(!RD_IsBusy() && HAS_FLAG(&symbol, SymbolFlags_Weak));

    actions[DisassemblerHooks::Action_CallGraph]->setText(QString("Callgraph %1").arg(symbolname));
    actions[DisassemblerHooks::Action_CallGraph]->setVisible(!RD_IsBusy() && IS_TYPE(&symbol, SymbolType_Function));

    actions[DisassemblerHooks::Action_Follow]->setText(QString("Follow %1").arg(symbolname));
    actions[DisassemblerHooks::Action_Follow]->setVisible(IS_TYPE(&symbol, SymbolType_Label));

    actions[DisassemblerHooks::Action_Comment]->setVisible(!RD_IsBusy() && IS_TYPE(&item, DocumentItemType_Instruction));

    actions[DisassemblerHooks::Action_HexDump]->setVisible(hassymbolsegment && HAS_FLAG(&symbolsegment, SegmentFlags_Bss));
    actions[DisassemblerHooks::Action_HexDumpFunction]->setVisible(hasitemsegment && !HAS_FLAG(&itemsegment, SegmentFlags_Bss) && HAS_FLAG(&itemsegment, SegmentFlags_Code));
}

ITableTab* DisassemblerHooks::findSymbolModelInTabs(type_t type, flag_t flags) const
{
    for(int i = 0; i < m_disassemblertabs->count(); i++)
    {
        auto* tabletab = dynamic_cast<ITableTab*>(m_disassemblertabs->widget(i));
        if(!tabletab) continue;

        auto* symboltablemodel = dynamic_cast<SymbolTableModel*>(tabletab->model());
        if(!symboltablemodel || (symboltablemodel->symbolType() != type)) continue;
        if(symboltablemodel->symbolFlags() != flags) continue;
        return tabletab;
    }

    return nullptr;
}

void DisassemblerHooks::listenEvents(const RDEventArgs* e)
{
    switch(e->eventid)
    {
        case Event_BusyChanged:
            QMetaObject::invokeMethod(DisassemblerHooks::instance(), "updateViewWidgets", Qt::QueuedConnection, Q_ARG(bool, RD_IsBusy()));
            break;

        case Event_CursorPositionChanged: {
            auto* hooks = DisassemblerHooks::instance();
            const auto* ce  = reinterpret_cast<const RDCursorEventArgs*>(e);

            if(hooks->m_activecommandtab) {
                if(hooks->m_activecommandtab->command()->cursor() != ce->sender) return;
                hooks->statusAddress(hooks->m_activecommandtab->command());
            }
            else rd_status(std::string());
            break;
        }

        case Event_Error: {
            const auto* ee = reinterpret_cast<const RDErrorEventArgs*>(e);
            QMetaObject::invokeMethod(DisassemblerHooks::instance(), "showMessage", Qt::QueuedConnection,
                                      Q_ARG(QString, "Error"),
                                      Q_ARG(QString, ee->message),
                                      Q_ARG(size_t, QMessageBox::Critical));
            break;
        }
    }
}

TableTab* DisassemblerHooks::createTable(ListingItemModel* model, const QString& title)
{
    TableTab* tabletab = new TableTab(model);
    model->setParent(tabletab);
    tabletab->setWindowTitle(title);
    return tabletab;
}

void DisassemblerHooks::loadDisassemblerView(RDLoaderPlugin* loader, RDAssemblerPlugin* assembler, const RDLoaderRequest& req, const RDLoaderBuildRequest& buildreq)
{
    this->close(false);       // Remove old docks
    this->clearOutput();      // Clear output
    if(m_worker.valid()) m_worker.get();

    RDEvent_Subscribe(this, &DisassemblerHooks::listenEvents, nullptr);
    RDDisassembler* disassembler = RDDisassembler_Create(&req, loader, assembler);
    m_disassemblerview = new DisassemblerView(disassembler, m_mainwindow);

    m_worker = std::async([&, disassembler, buildreq]() {
        RDLoader* ldr = RDDisassembler_GetLoader(disassembler);

        if(RDLoader_GetFlags(ldr) & LoaderFlags_CustomAddressing) RDLoader_Build(ldr, &buildreq);
        else RDLoader_Load(ldr);

        RD_Disassemble(disassembler);
        QMetaObject::invokeMethod(DisassemblerHooks::instance(), "enableViewCommands", Qt::QueuedConnection, Q_ARG(bool, true));
    });
}

void DisassemblerHooks::hook()
{
    m_lblstatusicon = m_mainwindow->findChild<QLabel*>(HOOK_STATUS_ICON);
    m_pbproblems = m_mainwindow->findChild<QPushButton*>(HOOK_PROBLEMS);
    m_mnuwindow = m_mainwindow->findChild<QMenu*>(HOOK_MENU_WINDOW);
    m_mnudev = m_mainwindow->findChild<QMenu*>(HOOK_MENU_DEVELOPMENT);
    m_toolbar = m_mainwindow->findChild<QToolBar*>(HOOK_TOOLBAR);
    m_disassemblertabs = m_mainwindow->findChild<DisassemblerTabs*>(HOOK_TABS);
    this->addWelcomeTab();

    auto actions = m_mnudev->actions();
    for(int i = 0; i < actions.size(); i++) actions[i]->setShortcut(QKeySequence(QString("CTRL+SHIFT+F%1").arg(i + 1)));

    connect(m_toolbar, &QToolBar::actionTriggered, this, &DisassemblerHooks::onToolBarActionTriggered);
    connect(m_mnuwindow, &QMenu::triggered, this, &DisassemblerHooks::onWindowActionTriggered);

    this->dock(new OutputDock(m_mainwindow), Qt::BottomDockWidgetArea);
    this->enableCommands(nullptr);
    this->enableViewCommands(false);
    this->loadRecents();
}

void DisassemblerHooks::showLoaders(const QString& filepath, RDBuffer* buffer)
{
    QByteArray rawfilepath = filepath.toUtf8();
    RDLoaderRequest req = { rawfilepath.data(), buffer };

    LoaderDialog dlgloader(&req, m_mainwindow);
    if(dlgloader.exec() != LoaderDialog::Accepted) return;

    RDLoaderPlugin* ploader = dlgloader.selectedLoader();
    RDAssemblerPlugin* passembler = dlgloader.selectedAssembler();

    if(!passembler)
    {
        QMessageBox::information(m_mainwindow, "Assembler Error",  QString("Cannot find assembler '%1' for '%2'").arg(RDLoader_GetAssemblerId(ploader), ploader->name));

        connect(&dlgloader, &LoaderDialog::destroyed, this, [ploader]() {
            RDPlugin_Free(reinterpret_cast<RDPluginHeader*>(ploader));
        });

        return;
    }

    rd_log(qUtf8Printable(QString("Selected loader '%1' with '%2' assembler").arg(ploader->name, passembler->name)));

    m_fileinfo = QFileInfo(filepath);
    this->loadDisassemblerView(ploader, passembler, req, dlgloader.buildRequest());
}

void DisassemblerHooks::addWelcomeTab() { m_disassemblertabs->addTab(new WelcomeTab(), QString()); }

QMenu* DisassemblerHooks::createActions(IDisassemblerCommand* command)
{
    QMenu* contextmenu = new QMenu(command->widget());
    std::unordered_map<int, QAction*> actions;

    actions[DisassemblerHooks::Action_Rename] = contextmenu->addAction("Rename", this, [&, command]() {
        RDSymbol symbol;
        if(!command->getSelectedSymbol(&symbol)) return;

        RDDocument* doc = RDDisassembler_GetDocument(command->disassembler());
        const char* symbolname = RDDocument_GetSymbolName(doc, symbol.address);
        if(!symbolname) return;

        bool ok = false;
        QString res = QInputDialog::getText(command->widget(),
                                            "Rename @ " + QString::fromStdString(rd_tohexauto(symbol.address)),
                                            "Symbol name:", QLineEdit::Normal, symbolname, &ok);

        if(!ok) return;
        RDDocument_Rename(doc, symbol.address, qUtf8Printable(res));
    }, QKeySequence(Qt::Key_N));

    actions[DisassemblerHooks::Action_Comment] = contextmenu->addAction("Comment", this, [&, command]() {
        RDDocumentItem item;
        if(!command->getCurrentItem(&item)) return;

        RDDocument* doc = RDDisassembler_GetDocument(command->disassembler());

        bool ok = false;
        QString res = QInputDialog::getMultiLineText(command->widget(),
                                                     "Comment @ " + QString::fromStdString(rd_tohexauto(item.address)),
                                                     "Insert a comment (leave blank to remove):",
                                                     RDDocument_GetComments(doc, item.address, "\n"), &ok);

        if(!ok) return;
        RDDocument_Comment(doc, item.address, qUtf8Printable(res));
    }, QKeySequence(Qt::Key_Semicolon));

    contextmenu->addSeparator();

    actions[DisassemblerHooks::Action_XRefs] = contextmenu->addAction("Cross References", this, [&, command]() {
        RDSymbol symbol;
        if(!command->getSelectedSymbol(&symbol)) return;
        this->showReferences(command, symbol.address);
    }, QKeySequence(Qt::Key_X));

    actions[DisassemblerHooks::Action_Follow] = contextmenu->addAction("Follow", this, [command]() {
        RDSymbol symbol;
        if(!command->getSelectedSymbol(&symbol)) return false;
        return command->gotoAddress(symbol.address);
    });

    actions[DisassemblerHooks::Action_FollowPointerHexDump] = contextmenu->addAction("Follow pointer in Hex Dump", this, [&, command]() {
    });

    actions[DisassemblerHooks::Action_Goto] = contextmenu->addAction("Goto...", this, [&, command]() {
        this->showGoto(command);
    }, QKeySequence(Qt::Key_G));

    actions[DisassemblerHooks::Action_CallGraph] = contextmenu->addAction("Call Graph", this, [&, command]() {

    }, QKeySequence(Qt::CTRL + Qt::Key_G));

    contextmenu->addSeparator();

    actions[DisassemblerHooks::Action_HexDump] = contextmenu->addAction("Show Hex Dump", this, [&, command]() {
    }, QKeySequence(Qt::CTRL + Qt::Key_H));

    actions[DisassemblerHooks::Action_HexDumpFunction] = contextmenu->addAction("Hex Dump Function", this, [&, command]() {
        RDDocumentItem item;
        if(!command->getCurrentItem(&item)) return;

        RDSymbol symbol;
        const char* hexdump = RDDisassembler_FunctionHexDump(command->disassembler(), item.address, &symbol);
        if(!hexdump) return;

        RDDocument* doc = RDDisassembler_GetDocument(command->disassembler());
        const char* name = RDDocument_GetSymbolName(doc, symbol.address);
        RD_Log(qUtf8Printable(QString("%1: %2").arg(name, hexdump)));
    });

    actions[DisassemblerHooks::Action_CreateFunction] = contextmenu->addAction("Create Function", this, [&, command]() {

    }, QKeySequence(Qt::SHIFT + Qt::Key_C));

    contextmenu->addSeparator();
    actions[DisassemblerHooks::Action_Back] = contextmenu->addAction("Back", this, [command]() { command->goBack(); }, QKeySequence(Qt::CTRL + Qt::Key_Left));
    actions[DisassemblerHooks::Action_Forward] = contextmenu->addAction("Forward", this, [command]() { command->goForward(); }, QKeySequence(Qt::CTRL + Qt::Key_Right));
    contextmenu->addSeparator();
    actions[DisassemblerHooks::Action_Copy] = contextmenu->addAction("Copy", this, [command]() { command->copy(); }, QKeySequence(QKeySequence::Copy));

    actions[DisassemblerHooks::Action_ItemInformation] = contextmenu->addAction("Item Information", this, [&, command]() {
        ItemInformationDialog dlgiteminfo(command, m_mainwindow);
        dlgiteminfo.exec();
    });

    for(auto& [type, action] : actions) action->setData(type);

    command->widget()->addAction(actions[DisassemblerHooks::Action_Rename]);
    command->widget()->addAction(actions[DisassemblerHooks::Action_XRefs]);
    command->widget()->addAction(actions[DisassemblerHooks::Action_Comment]);
    command->widget()->addAction(actions[DisassemblerHooks::Action_Goto]);
    command->widget()->addAction(actions[DisassemblerHooks::Action_CallGraph]);
    command->widget()->addAction(actions[DisassemblerHooks::Action_HexDump]);
    command->widget()->addAction(actions[DisassemblerHooks::Action_CreateFunction]);
    command->widget()->addAction(actions[DisassemblerHooks::Action_Back]);
    command->widget()->addAction(actions[DisassemblerHooks::Action_Forward]);
    command->widget()->addAction(actions[DisassemblerHooks::Action_Copy]);

    connect(contextmenu, &QMenu::aboutToShow, this, &DisassemblerHooks::adjustActions);
    return contextmenu;
}

void DisassemblerHooks::setActiveCommandTab(ICommandTab* commandtab) { m_activecommandtab = commandtab; }
void DisassemblerHooks::focusOn(QWidget* w) { m_disassemblertabs->setCurrentWidget(w); }

void DisassemblerHooks::loadRecents()
{
    QAction* actrecents = m_mainwindow->findChild<QAction*>(HOOK_ACTION_RECENT_FILES);
    if(!actrecents) return;

    REDasmSettings settings;
    QStringList recents = settings.recentFiles();
    actrecents->setEnabled(!recents.empty());

    QMenu* recentsmenu = new QMenu(m_mainwindow);

    for(int i = 0; i < MAX_RECENT_FILES; i++)
    {
        if(i >= recents.length())
        {
            QAction* action = recentsmenu->addAction(QString());
            action->setVisible(false);
            continue;
        }

        if(!QFileInfo(recents[i]).exists()) continue;

        QAction* action = recentsmenu->addAction(QString("%1 - %2").arg(i).arg(recents[i]));
        action->setData(recents[i]);

        connect(action, &QAction::triggered, this, [=]() {
            this->load(action->data().toString());
        });
    }

    if(actrecents->menu()) actrecents->menu()->deleteLater();
    actrecents->setMenu(recentsmenu);
}

void DisassemblerHooks::load(const QString& filepath)
{
    QFileInfo fi(filepath);
    QDir::setCurrent(fi.path());

    REDasmSettings settings;
    settings.updateRecentFiles(filepath);
    this->loadRecents();

    if(this->openDatabase(filepath)) return;

    RDBuffer* buffer = RDBuffer_CreateFromFile(qUtf8Printable(filepath));
    if(buffer && RDBuffer_Size(buffer)) this->showLoaders(filepath, buffer);
    else if(buffer) RD_Free(buffer);
}

void DisassemblerHooks::tab(QWidget* w, int index)
{
    if(index != -1) m_disassemblertabs->insertTab(index, w, w->windowTitle());
    else m_disassemblertabs->addTab(w, w->windowTitle());
}

void DisassemblerHooks::tabify(QDockWidget* first, QDockWidget* second)
{
    first->setParent(m_mainwindow);  // Take ownership
    second->setParent(m_mainwindow); // Take ownership
    m_mainwindow->tabifyDockWidget(first, second);
}

void DisassemblerHooks::dock(QWidget* w, Qt::DockWidgetArea area)
{
    QDockWidget* dw = dynamic_cast<QDockWidget*>(w);

    if(!dw)
    {
        dw = new QDockWidget(m_mainwindow);
        w->setParent(dw); // Take ownership
        dw->setWindowTitle(w->windowTitle());
        dw->setWidget(w);
    }

    m_mainwindow->addDockWidget(area, dw);
}

OutputDock* DisassemblerHooks::outputDock() const { return m_mainwindow->findChild<OutputDock*>(QString(), Qt::FindDirectChildrenOnly); }

void DisassemblerHooks::close(bool showwelcome)
{
    while(m_disassemblertabs->count()) {
        QWidget* w = m_disassemblertabs->widget(0);
        m_disassemblertabs->removeTab(0);
        w->deleteLater();
    }

    auto docks = m_mainwindow->findChildren<QDockWidget*>(QString(), Qt::FindDirectChildrenOnly);

    for(const auto& child : docks) {
        if(dynamic_cast<OutputDock*>(child)) continue;
        this->undock(child);
    }

    RD_Status("");
    this->enableViewCommands(false);
    m_activecommandtab = nullptr;

    if(!m_disassemblerview) return;
    m_disassemblerview->dispose();
    m_disassemblerview = nullptr;

    if(showwelcome) this->addWelcomeTab();
}

void DisassemblerHooks::clearOutput()
{
    OutputDock* outputpart = this->outputDock();
    if(outputpart) outputpart->clear();
}

void DisassemblerHooks::enableMenu(QMenu* menu, bool enable)
{
    auto actions = menu->actions();
    std::for_each(actions.begin(), actions.end(), [enable](QAction* a) { a->setEnabled(enable); });

    if(dynamic_cast<QMenuBar*>(menu->parentWidget())) menu->menuAction()->setVisible(enable);
    menu->setEnabled(enable);
}

bool DisassemblerHooks::openDatabase(const QString& filepath)
{
    return false;
}

void DisassemblerHooks::enableViewCommands(bool enable)
{
    this->enableMenu(m_mnudev, enable);
    this->enableMenu(m_mnuwindow, enable);

    auto actions = m_toolbar->actions();
    actions[1]->setEnabled(enable);

    QAction* act = m_mainwindow->findChild<QAction*>(HOOK_ACTION_SAVE_AS);
    act->setEnabled(enable);

    act = m_mainwindow->findChild<QAction*>(HOOK_ACTION_CLOSE);
    act->setEnabled(enable);
}

void DisassemblerHooks::showMessage(const QString& title, const QString& msg, size_t icon)
{
    QMessageBox msgbox(m_mainwindow);
    msgbox.setWindowTitle(title);
    msgbox.setText(msg);
    msgbox.setIcon(static_cast<QMessageBox::Icon>(icon));
    msgbox.exec();
}

void DisassemblerHooks::updateViewWidgets(bool busy)
{
    if(!m_disassemblerview)
    {
        m_toolbar->actions()[4]->setEnabled(false);
        m_lblstatusicon->setVisible(false);
        m_pbproblems->setVisible(false);
        m_mainwindow->setWindowTitle(QString());
        return;
    }

    if(busy)
    {
        m_mainwindow->setWindowTitle(QString("%1 (Working)").arg(m_fileinfo.fileName()));
        m_lblstatusicon->setStyleSheet("color: red;");
    }
    else
    {
        m_mainwindow->setWindowTitle(m_fileinfo.fileName());
        m_lblstatusicon->setStyleSheet("color: green;");
    }

    m_toolbar->actions()[4]->setEnabled(!busy); // Goto
    m_lblstatusicon->setVisible(true);
    m_pbproblems->setVisible(!busy && RD_HasProblems());
    m_pbproblems->setText(QString::number(RD_ProblemsCount()) + " problem(s)");
}

void DisassemblerHooks::enableCommands(QWidget* w)
{
    auto actions = m_toolbar->actions();

    if(!w)
    {
        for(int i = 2; i < actions.size(); i++)
            actions[i]->setVisible(false);

        return;
    }

    auto* commandtab = dynamic_cast<ICommandTab*>(w);
    actions[2]->setVisible(commandtab); // Back
    actions[3]->setVisible(commandtab); // Forward
    actions[4]->setVisible(commandtab); // Goto

    auto* tabletab = dynamic_cast<ITableTab*>(w);
    actions[5]->setVisible(tabletab); // Filter
}

void DisassemblerHooks::updateCommandStates(QWidget* w) const
{
    auto actions = m_toolbar->actions();

    if(auto* commandtab = dynamic_cast<ICommandTab*>(w))
    {
        actions[2]->setEnabled(commandtab->command()->canGoBack());
        actions[3]->setEnabled(commandtab->command()->canGoForward());
    }
}
