#include "disassemblerhooks.h"
#include "../dialogs/tabledialog/tabledialog.h"
#include "../dialogs/aboutdialog/aboutdialog.h"
#include "../dialogs/settingsdialog/settingsdialog.h"
#include "../dialogs/loaderdialog/loaderdialog.h"
#include "../dialogs/referencesdialog/referencesdialog.h"
#include "../dialogs/gotodialog/gotodialog.h"
#include "../dialogs/dev/functiongraphdialog/functiongraphdialog.h"
#include "../widgets/tabs/welcometab/welcometab.h"
#include "../widgets/docks/outputdock/outputdock.h"
#include "../widgets/tabs/tabletab/tabletab.h"
#include "../widgets/disassemblertabs/disassemblertabs.h"
#include "../widgets/disassemblerview.h"
#include "../models/dev/blocklistmodel.h"
#include "../models/listingitemmodel.h"
#include "../models/symboltablemodel.h"
#include "../models/segmentsmodel.h"
#include "../redasmsettings.h"
#include "../redasmfonts.h"
#include <QtConcurrent/QtConcurrent>
#include <QFutureWatcher>
#include <QApplication>
#include <QInputDialog>
#include <QMessageBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QToolBar>
#include <QMenuBar>
#include <QMenu>
#include <unordered_map>
#include <type_traits>
#include <rdapi/rdapi.h>

DisassemblerHooks DisassemblerHooks::m_instance;

DisassemblerHooks::DisassemblerHooks(QObject* parent): QObject(parent) { }
DisassemblerHooks::~DisassemblerHooks() { if(m_busyevent) RDEvent_Unsubscribe(m_busyevent); }

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

TableTab* DisassemblerHooks::showSegments(ICommandTab* commandtab, Qt::DockWidgetArea area)
{
    TableTab* tabletab = this->createTable(commandtab, new SegmentsModel(), "Segments");
    tabletab->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    tabletab->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    tabletab->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    tabletab->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    tabletab->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    tabletab->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    tabletab->setSectionResizeMode(6, QHeaderView::Stretch);
    tabletab->setSectionResizeMode(7, QHeaderView::Stretch);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

TableTab* DisassemblerHooks::showFunctions(ICommandTab* commandtab, Qt::DockWidgetArea area)
{
    TableTab* tabletab = this->createTable(commandtab, new ListingItemModel(DocumentItemType_Function), "Functions");
    tabletab->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    tabletab->setSectionResizeMode(1, QHeaderView::Stretch);
    tabletab->setColumnHidden(2);
    tabletab->setColumnHidden(3);
    tabletab->moveSection(2, 1);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

TableTab* DisassemblerHooks::showExports(ICommandTab* commandtab, Qt::DockWidgetArea area)
{
    auto* model = new SymbolTableModel(DocumentItemType_All);
    model->setSymbolType(SymbolType_Function);
    model->setSymbolFlags(SymbolFlags_Export);

    TableTab* tabletab = this->createTable(commandtab, model, "Exports");
    tabletab->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    tabletab->setSectionResizeMode(1, QHeaderView::Stretch);
    tabletab->setSectionResizeMode(2, QHeaderView::ResizeToContents);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

TableTab* DisassemblerHooks::showImports(ICommandTab* commandtab, Qt::DockWidgetArea area)
{
    auto* model = new SymbolTableModel(DocumentItemType_Symbol);
    model->setSymbolType(SymbolType_Import);

    TableTab* tabletab = this->createTable(commandtab, model, "Imports");
    tabletab->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    tabletab->setSectionResizeMode(1, QHeaderView::Stretch);
    tabletab->setSectionResizeMode(2, QHeaderView::ResizeToContents);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

TableTab* DisassemblerHooks::showStrings(ICommandTab* commandtab, Qt::DockWidgetArea area)
{
    auto* model = new SymbolTableModel(DocumentItemType_Symbol);
    model->setSymbolType(SymbolType_String);

    TableTab* tabletab = this->createTable(commandtab, model, "Strings");
    tabletab->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    tabletab->setSectionResizeMode(1, QHeaderView::Stretch);
    tabletab->setSectionResizeMode(2, QHeaderView::ResizeToContents);

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

    td->setModel(new BlockListModel());
    td->show();
}

QWidget* DisassemblerHooks::currentTab() const { return m_disassemblertabs->currentWidget(); }

void DisassemblerHooks::undock(QDockWidget* dw)
{
    m_mainwindow->removeDockWidget(dw);
    dw->deleteLater();
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

void DisassemblerHooks::onBackClicked()
{
    auto* commandtab = dynamic_cast<ICommandTab*>(m_disassemblertabs->currentWidget());
    if(commandtab) commandtab->command()->goBack();
}

void DisassemblerHooks::onForwardClicked()
{
    auto* commandtab = dynamic_cast<ICommandTab*>(m_disassemblertabs->currentWidget());
    if(commandtab) commandtab->command()->goForward();
}

void DisassemblerHooks::onGotoClicked()
{
    auto* commandtab = dynamic_cast<ICommandTab*>(m_disassemblertabs->currentWidget());
    if(commandtab) this->showGoto(commandtab->command());
}

void DisassemblerHooks::onFilterClicked()
{
    auto* tabletab = dynamic_cast<ITableTab*>(m_disassemblertabs->currentWidget());
    if(tabletab) tabletab->toggleFilter();
}

TableTab* DisassemblerHooks::createTable(ICommandTab* commandtab, ListingItemModel* model, const QString& title)
{
    TableTab* tabletab = new TableTab(commandtab, model);
    model->setParent(tabletab);
    tabletab->setWindowTitle(title);
    return tabletab;
}

void DisassemblerHooks::loadDisassemblerView(RDDisassembler* disassembler, const RDLoaderBuildRequest& req)
{
    this->close(false);       // Remove old docks
    this->clearOutput();      // Clear output

    m_disassemblerview = new DisassemblerView(disassembler, m_mainwindow);
    auto* futurewatcher = new QFutureWatcher<void>(this);
    connect(futurewatcher, &QFutureWatcher<void>::finished, futurewatcher, &QFutureWatcher<void>::deleteLater);

    futurewatcher->setFuture(QtConcurrent::run([&, disassembler, req]() {
        RDLoader* ldr = RDDisassembler_GetLoader(disassembler);

        if(RDLoader_GetFlags(ldr) & LoaderFlags_CustomAddressing) RDLoader_Build(ldr, &req);
        else RDLoader_Load(ldr);

        RD_Disassemble(disassembler);
        QMetaObject::invokeMethod(DisassemblerHooks::instance(), "enableViewCommands", Qt::QueuedConnection, Q_ARG(bool, true));
    }));
}

void DisassemblerHooks::hook()
{
    m_lblstatusicon = m_mainwindow->findChild<QLabel*>(HOOK_STATUS_ICON);
    m_pbproblems = m_mainwindow->findChild<QPushButton*>(HOOK_PROBLEMS);
    m_mnuviews = m_mainwindow->findChild<QMenu*>(HOOK_MENU_VIEWS);
    m_mnudev = m_mainwindow->findChild<QMenu*>(HOOK_MENU_DEVELOPMENT);
    m_toolbar = m_mainwindow->findChild<QToolBar*>(HOOK_TOOLBAR);
    m_disassemblertabs = m_mainwindow->findChild<DisassemblerTabs*>(HOOK_TABS);
    this->addWelcomeTab();

    auto actions = m_mnudev->actions();
    for(int i = 0; i < actions.size(); i++) actions[i]->setShortcut(QKeySequence(QString("CTRL+SHIFT+F%1").arg(i + 1)));

    actions = m_toolbar->actions();
    connect(actions[2], &QAction::triggered, this, &DisassemblerHooks::onBackClicked);
    connect(actions[3], &QAction::triggered, this, &DisassemblerHooks::onForwardClicked);
    connect(actions[4], &QAction::triggered, this, &DisassemblerHooks::onGotoClicked);
    connect(actions[5], &QAction::triggered, this, &DisassemblerHooks::onFilterClicked);

    this->dock(new OutputDock(m_mainwindow), Qt::BottomDockWidgetArea);
    this->enableCommands(nullptr);
    this->enableViewCommands(false);
    this->loadRecents();

    m_busyevent = RDEvent_Subscribe(Event_BusyChanged, [](const RDEventArgs*, void* userdata) {
        auto* thethis = reinterpret_cast<DisassemblerHooks*>(userdata);
        QMetaObject::invokeMethod(thethis, "updateViewWidgets", Qt::QueuedConnection, Q_ARG(bool, RD_IsBusy()));
    }, this);
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
    RDDisassembler* disassembler = RDDisassembler_Create(&req, ploader, passembler);
    this->loadDisassemblerView(disassembler, dlgloader.buildRequest());
}

void DisassemblerHooks::addWelcomeTab() { m_disassemblertabs->addTab(new WelcomeTab(), QString()); }

QMenu* DisassemblerHooks::createActions(IDisassemblerCommand* command)
{
    QMenu* contextmenu = new QMenu(command->widget());
    std::unordered_map<int, QAction*> actions;

    actions[DisassemblerHooks::Action_Rename] = contextmenu->addAction("Rename", this, [&, command]() {

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
        const char* hexdump = RD_HexDump(command->disassembler(), item.address, &symbol);
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

void DisassemblerHooks::tab(QWidget* w) { m_disassemblertabs->addTab(w, w->windowTitle()); }

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

    if(!m_disassemblerview) return;
    m_disassemblerview->deleteLater();
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
    this->enableMenu(m_mnuviews, enable);

    auto actions = m_toolbar->actions();
    actions[1]->setEnabled(enable);

    QAction* act = m_mainwindow->findChild<QAction*>(HOOK_ACTION_SAVE_AS);
    act->setEnabled(enable);

    act = m_mainwindow->findChild<QAction*>(HOOK_ACTION_CLOSE);
    act->setEnabled(enable);
}

void DisassemblerHooks::updateViewWidgets(bool busy)
{
    if(!m_disassemblerview)
    {
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
