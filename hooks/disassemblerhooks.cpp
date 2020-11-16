#include "disassemblerhooks.h"
#include "../dialogs/tabledialog/tabledialog.h"
#include "../dialogs/aboutdialog/aboutdialog.h"
#include "../dialogs/problemsdialog/problemsdialog.h"
#include "../dialogs/settingsdialog/settingsdialog.h"
#include "../dialogs/analyzerdialog/analyzerdialog.h"
#include "../dialogs/loaderdialog/loaderdialog.h"
#include "../dialogs/devdialog/devdialog.h"
#include "../dialogs/databasedialog/databasedialog.h"
#include "../widgets/docks/outputdock/outputdock.h"
#include "../widgets/disassemblerview.h"
#include "../widgets/welcomewidget.h"
#include "../models/dev/blocklistmodel.h"
#include "../models/listingitemmodel.h"
#include "../renderer/surfaceqt.h"
#include "../redasmsettings.h"
#include "../redasmfonts.h"
#include <QMessageBox>
#include <QApplication>
#include <QFileDialog>
#include <QFileInfo>
#include <QToolBar>
#include <QMenuBar>
#include <rdapi/rdapi.h>

#define MAX_FUNCTION_NAME 50

DisassemblerHooks DisassemblerHooks::m_instance;

DisassemblerHooks::DisassemblerHooks(QObject* parent): QObject(parent) { }

void DisassemblerHooks::initialize(QMainWindow* mainwindow)
{
    DisassemblerHooks::m_instance.m_mainwindow = mainwindow;
    DisassemblerHooks::m_instance.hook();
}

DisassemblerHooks* DisassemblerHooks::instance() { return &m_instance; }
QMainWindow* DisassemblerHooks::mainWindow() const { return m_mainwindow; }
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
void DisassemblerHooks::showDeveloperTools() { if(m_devdialog) m_devdialog->show(); }

void DisassemblerHooks::showDatabase()
{
    DatabaseDialog dbdialog(m_mainwindow);
    dbdialog.exec();
}

void DisassemblerHooks::showProblems() { ProblemsDialog dlgproblems(this->activeContext(), m_mainwindow); dlgproblems.exec(); }
void DisassemblerHooks::focusOn(QWidget* w) { if(m_disassemblerview) m_disassemblerview->focusOn(w); }

SurfaceQt* DisassemblerHooks::activeSurface() const
{
    if(!m_disassemblerview) return nullptr;

    auto* activesurface = RDContext_GetActiveSurface(m_disassemblerview->context().get());
    if(!activesurface) return nullptr;
    return reinterpret_cast<SurfaceQt*>(RDSurface_GetUserData(activesurface));
}

RDContextPtr DisassemblerHooks::activeContext() const  {  return m_disassemblerview ? m_disassemblerview->context() : nullptr; }

void DisassemblerHooks::undock(QDockWidget* dw)
{
    m_mainwindow->removeDockWidget(dw);
    dw->deleteLater();
}

void DisassemblerHooks::onToolBarActionTriggered(QAction* action)
{
    auto* surface = this->activeSurface();
    if(!surface) return;

    int idx = m_toolbar->actions().indexOf(action);

    switch(idx)
    {
        case 2: surface->goBack(); break;
        case 3: surface->goForward(); break;
        //case 4: this->showGoto(); break;

        case 5: {
            auto* tabletab = dynamic_cast<ITableTab*>(m_disassemblerview->currentWidget());
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
            auto* surface = this->activeSurface();
            if(!surface) surface = m_disassemblerview->showListing();
            if(surface) this->focusOn(surface->widget());
            break;
        }

        case 1: m_disassemblerview->showSegments();  break;
        case 2: m_disassemblerview->showFunctions(); break;
        case 3: m_disassemblerview->showExports();   break;
        case 4: m_disassemblerview->showImports();   break;
        case 5: m_disassemblerview->showStrings();   break;
        default: break;
    }
}

void DisassemblerHooks::statusAddress(const SurfaceQt* surface) const
{
    if(!surface || RDContext_IsBusy(surface->context().get())) return;

    RDDocument* doc = RDContext_GetDocument(surface->context().get());

    RDDocumentItem item;
    if(!surface->getCurrentItem(&item)) return;

    RDLoader* ldr = RDContext_GetLoader(surface->context().get());

    RDSegment segment;
    bool hassegment = RDDocument_GetSegmentAddress(doc, item.address, &segment);

    RDLocation functionstart = RDContext_GetFunctionStart(surface->context().get(), item.address);
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

        if(func.size() > MAX_FUNCTION_NAME)
            func = func.left(MAX_FUNCTION_NAME) + "..."; // Elide long function names

        if(item.address > functionstart.value)
            func += "+" + QString::fromUtf8(RD_ToHexBits(item.address - functionstart.value, 8, false));
        else if(item.address < functionstart.value)
            func += QString::number(static_cast<std::make_signed<size_t>::type>(item.address - functionstart.value));

        s = QString::fromWCharArray(L"<b>Function: </b>%1\u00A0\u00A0").arg(func.toHtmlEscaped()) + s;
    }

    RD_Status(qUtf8Printable(s));
}

void DisassemblerHooks::loadDisassemblerView(const RDContextPtr& ctx)
{
    this->close(false);

    m_devdialog = new DevDialog(ctx, m_mainwindow);
    m_disassemblerview = new DisassemblerView();
    m_disassemblerview->setContext(ctx);
    this->replaceWidget(m_disassemblerview);
}

void DisassemblerHooks::hook()
{
    m_lblstatusicon = m_mainwindow->findChild<QLabel*>(HOOK_STATUS_ICON);
    m_pbrenderer = m_mainwindow->findChild<QPushButton*>(HOOK_RENDERER);
    m_pbproblems = m_mainwindow->findChild<QPushButton*>(HOOK_PROBLEMS);
    m_mnuwindow = m_mainwindow->findChild<QMenu*>(HOOK_MENU_WINDOW);
    m_toolbar = m_mainwindow->findChild<QToolBar*>(HOOK_TOOLBAR);
    this->showWelcome();

    QAction* act = m_mainwindow->findChild<QAction*>(HOOK_ACTION_DATABASE);
    connect(act, &QAction::triggered, this, [&]() { this->showDatabase(); });

    connect(m_pbproblems, &QPushButton::clicked, this, [&]() { this->showProblems(); });
    connect(m_toolbar, &QToolBar::actionTriggered, this, &DisassemblerHooks::onToolBarActionTriggered);
    connect(m_mnuwindow, &QMenu::triggered, this, &DisassemblerHooks::onWindowActionTriggered);

    connect(m_pbrenderer, &QPushButton::clicked, this, [&]() {
        const RDContextPtr& ctx = this->activeContext();
        RDContext_SetFlags(ctx.get(), ContextFlags_ShowRDIL, !RDContext_HasFlag(ctx.get(), ContextFlags_ShowRDIL));
        this->checkListingMode();
    });

    this->dock(new OutputDock(m_mainwindow), Qt::BottomDockWidgetArea);
    this->enableCommands(nullptr);
    this->enableViewCommands(false);
    this->loadRecents();
}

void DisassemblerHooks::showLoaders(const QString& filepath, RDBuffer* buffer)
{
    RDContextPtr ctx(RDContext_Create(), RDObjectDeleter());
    QByteArray rawfilepath = filepath.toUtf8();
    RDLoaderRequest req = { rawfilepath.data(), buffer, { } };

    LoaderDialog dlgloader(ctx, &req, m_mainwindow);

    if(dlgloader.exec() != LoaderDialog::Accepted)
    {
        RDObject_Free(buffer);
        return;
    }

    this->clearOutput();

    req.buildparams = dlgloader.buildRequest();
    RDDisassembler* disassembler = RDContext_BuildDisassembler(ctx.get(), &req, dlgloader.selectedLoaderEntry(), dlgloader.selectedAssemblerEntry());
    if(!disassembler) return;

    const RDLoader* loader = RDContext_GetLoader(ctx.get());
    const RDAssembler* assembler = RDContext_GetAssembler(ctx.get());
    rd_log(qUtf8Printable(QString("Selected loader '%1' with '%2' assembler").arg(RDLoader_GetName(loader), RDAssembler_GetName(assembler))));

    AnalyzerDialog dlganalyzer(ctx, m_mainwindow);
    if(dlganalyzer.exec() != AnalyzerDialog::Accepted) return;

    m_fileinfo = QFileInfo(filepath);
    this->loadDisassemblerView(ctx);
}

void DisassemblerHooks::showWelcome() { this->replaceWidget(new WelcomeWidget()); }

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
    else if(buffer) RDObject_Free(buffer);
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

void DisassemblerHooks::checkListingMode()
{
    if(RDContext_HasFlag(this->activeContext().get(), ContextFlags_ShowRDIL)) m_pbrenderer->setText("RDIL");
    else m_pbrenderer->setText("Listing");
}

void DisassemblerHooks::close(bool showwelcome)
{
    this->enableViewCommands(false);
    this->enableCommands(nullptr);

    if(m_devdialog) m_devdialog->deleteLater();
    m_devdialog = nullptr;

    if(showwelcome) this->showWelcome(); // Replaces central widget, if any
    else if(m_disassemblerview) m_disassemblerview->deleteLater();
    m_disassemblerview = nullptr;
}

void DisassemblerHooks::replaceWidget(QWidget* w)
{
    QWidget* oldw = m_mainwindow->centralWidget();

    if(oldw)
    {
        connect(oldw, &QWidget::destroyed, this, [w, this]() {
            m_mainwindow->setCentralWidget(w);
        });

        oldw->deleteLater();
    }
    else
        m_mainwindow->setCentralWidget(w);
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

    if(this->activeContext())
    {
        m_pbproblems->setVisible(!busy && RDContext_HasProblems(this->activeContext().get()));
        m_pbproblems->setText(QString::number(RDContext_GetProblemsCount(this->activeContext().get())) + " problem(s)");
    }
    else
        m_pbproblems->setVisible(false);
}

void DisassemblerHooks::enableCommands(QWidget* w)
{
    QAction* act = m_mainwindow->findChild<QAction*>(HOOK_ACTION_DEVTOOLS);
    auto actions = m_toolbar->actions();

    if(!w)
    {
        for(int i = 2; i < actions.size(); i++)
            actions[i]->setVisible(false);

        act->setVisible(false);
        m_pbrenderer->setVisible(false);
        return;
    }

    auto* surfacetab = dynamic_cast<ISurfaceTab*>(w);
    this->checkListingMode();

    m_pbrenderer->setVisible(surfacetab);
    act->setVisible(surfacetab);

    actions[2]->setVisible(surfacetab); // Back
    actions[3]->setVisible(surfacetab); // Forward
    actions[4]->setVisible(surfacetab); // Goto

    auto* tabletab = dynamic_cast<ITableTab*>(w);
    actions[5]->setVisible(tabletab); // Filter
}

void DisassemblerHooks::updateCommandStates() const
{
    auto actions = m_toolbar->actions();
    auto* surface = this->activeSurface();
    actions[2]->setEnabled(surface && surface->canGoBack());
    actions[3]->setEnabled(surface && surface->canGoForward());
}
