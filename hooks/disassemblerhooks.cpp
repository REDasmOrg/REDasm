#include "disassemblerhooks.h"
#include "../dialogs/tabledialog/tabledialog.h"
#include "../dialogs/aboutdialog/aboutdialog.h"
#include "../dialogs/problemsdialog/problemsdialog.h"
#include "../dialogs/settingsdialog/settingsdialog.h"
#include "../dialogs/analyzerdialog/analyzerdialog.h"
#include "../dialogs/loaderdialog/loaderdialog.h"
#include "../dialogs/devdialog/devdialog.h"
#include "../dialogs/flcdialog/flcdialog.h"
#include "../dialogs/databasedialog/databasedialog.h"
#include "../widgets/listing/listingview.h"
#include "../widgets/disassemblerdocks.h"
#include "../widgets/callgraphview/callgraphview.h"
#include "../widgets/dashboard/welcomewidget.h"
#include "../widgets/outputwidget.h"
#include "../widgets/docks/dockwidget.h"
#include "../models/dev/blocklistmodel.h"
#include "../models/listingitemmodel.h"
#include "../renderer/surfaceqt.h"
#include "../redasmsettings.h"
#include "../redasmfonts.h"
#include "dockidentifiers.h"
#include <QDesktopServices>
#include <QMessageBox>
#include <QApplication>
#include <QVBoxLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QToolBar>
#include <QMenuBar>
#include <rdapi/rdapi.h>

#define MAX_FUNCTION_NAME  50
#define MAX_WINDOW_ACTIONS 10

DisassemblerHooks::DisassemblerHooks(QObject* parent): QObject(parent) { }

void DisassemblerHooks::initialize(KDDockWidgets::MainWindow* mainwindow)
{
    DisassemblerHooks::instance()->m_mainwindow = mainwindow;
    DisassemblerHooks::instance()->hook();
}

DisassemblerHooks* DisassemblerHooks::instance()
{
    static DisassemblerHooks m_instance;
    return &m_instance;
}

KDDockWidgets::MainWindow* DisassemblerHooks::mainWindow() { return DisassemblerHooks::instance()->m_mainwindow; }

DockWidget* DisassemblerHooks::dockify(QWidget* w, KDDockWidgets::DockWidget::Options options)
{
    auto* dock = new DockWidget(w->windowTitle(), options);
    dock->setWidget(w);
    return dock;
}

DockWidget* DisassemblerHooks::tabify(QWidget* w, KDDockWidgets::DockWidgetBase::Options options) { return DisassemblerHooks::tabify(DisassemblerHooks::dockify(w, options)); }

DockWidget* DisassemblerHooks::tabify(DockWidget* dock)
{
    DisassemblerHooks::mainWindow()->addDockWidgetAsTab(dock);
    return dock;
}

void DisassemblerHooks::focusOn(QWidget* w)
{
    QWidget* cw = w;

    while(cw)
    {
       auto* tw = dynamic_cast<DockWidget*>(cw);

       if(tw)
       {
           cw = tw;
           break;
       }

       cw = cw->parentWidget();
    }

    if(cw) static_cast<DockWidget*>(cw)->raise();
}

void DisassemblerHooks::log(const QString& s)
{
    auto* ow = this->outputWidget();
    if(ow) ow->log(s);
    else qDebug() << s;
}

void DisassemblerHooks::clearLog()
{
    auto* ow = this->outputWidget();
    if(ow) ow->clear();
}

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

void DisassemblerHooks::showFLC()
{
    if(!m_flcdialog) m_flcdialog = new FLCDialog(m_mainwindow);
    m_flcdialog->showFLC(this->activeContext());
}

void DisassemblerHooks::showCallGraph(rd_address address)
{
    auto* cgv = new CallGraphView(this->activeContext());
    this->showDialog("Callgraph @ " + QString::fromStdString(rd_tohex(address)), cgv);
    cgv->walk(address);
}

void DisassemblerHooks::showDeveloperTools() { if(m_devdialog) m_devdialog->show(); }

void DisassemblerHooks::showDatabase()
{
    DatabaseDialog dbdialog(this->activeContext(), m_mainwindow);
    dbdialog.exec();
}

void DisassemblerHooks::showProblems() { ProblemsDialog dlgproblems(this->activeContext(), m_mainwindow); dlgproblems.exec(); }

SurfaceQt* DisassemblerHooks::activeSurface()
{
    if(!DisassemblerHooks::activeContext()) return nullptr;
    auto* activesurface = RDContext_GetActiveSurface(DisassemblerHooks::activeContext().get());
    return activesurface ? reinterpret_cast<SurfaceQt*>(RDSurface_GetUserData(activesurface)) : nullptr;
}

RDContextPtr DisassemblerHooks::activeContext() { return DisassemblerHooks::instance()->m_disassemblerdocks ? DisassemblerHooks::instance()->m_disassemblerdocks->context() : nullptr; }

void DisassemblerHooks::statusAddress(const SurfaceQt* surface) const
{
    if(!surface || RDContext_IsBusy(surface->context().get())) return;

    RDDocument* doc = RDContext_GetDocument(surface->context().get());

    RDDocumentItem item;
    if(!surface->getCurrentItem(&item)) return;

    RDSegment segment;
    bool hassegment = RDDocument_GetSegmentAddress(doc, item.address, &segment);

    RDLocation functionstart = RDContext_GetFunctionStart(surface->context().get(), item.address);
    RDLocation offset = RD_Offset(surface->context().get(), item.address);

    QString segm = hassegment ? segment.name : "UNKNOWN",
            offs = hassegment && offset.valid ? RD_ToHexAuto(surface->context().get(), offset.value) : "UNKNOWN",
            addr = RD_ToHexAuto(surface->context().get(), item.address);

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

void DisassemblerHooks::loadDisassemblerDocks(const RDContextPtr& ctx)
{
    this->close(false);
    this->setTabBarVisible(true);

    m_devdialog = new DevDialog(ctx, m_mainwindow);
    m_disassemblerdocks = new DisassemblerDocks();
    m_disassemblerdocks->setContext(ctx);
}

void DisassemblerHooks::hook()
{
    m_lblstatusicon = m_mainwindow->findChild<QLabel*>(HOOK_STATUS_ICON);
    m_pbrenderer = m_mainwindow->findChild<QPushButton*>(HOOK_RENDERER);
    m_pbproblems = m_mainwindow->findChild<QPushButton*>(HOOK_PROBLEMS);
    m_mnuwindow = m_mainwindow->findChild<QMenu*>(HOOK_MENU_WINDOW);
    m_toolbar = m_mainwindow->findChild<QToolBar*>(HOOK_TOOLBAR);
    this->showWelcome();
    this->showOutput();

    QAction* act = m_mainwindow->findChild<QAction*>(HOOK_ACTION_DATABASE);
    connect(act, &QAction::triggered, this, [&]() { this->showDatabase(); });

    connect(m_pbproblems, &QPushButton::clicked, this, [&]() { this->showProblems(); });

    connect(m_pbrenderer, &QPushButton::clicked, this, [&]() {
        const RDContextPtr& ctx = this->activeContext();
        RDContext_SetFlags(ctx.get(), ContextFlags_ShowRDIL, !RDContext_HasFlag(ctx.get(), ContextFlags_ShowRDIL));
        this->checkListingMode();
    });

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
    if(!RDContext_Bind(ctx.get(), &req, dlgloader.selectedLoaderEntry(), dlgloader.selectedAssemblerEntry())) return;

    const RDLoader* loader = RDContext_GetLoader(ctx.get());
    const RDAssembler* assembler = RDContext_GetAssembler(ctx.get());
    rd_log(qUtf8Printable(QString("Selected loader '%1' with '%2' assembler").arg(RDLoader_GetName(loader), RDAssembler_GetName(assembler))));

    rd_log(qUtf8Printable(QString("Minimum string length set to %1").arg(dlgloader.selectedMinString())));
    RDContext_SetMinString(ctx.get(), dlgloader.selectedMinString());

    AnalyzerDialog dlganalyzer(ctx, m_mainwindow);
    if(dlganalyzer.exec() != AnalyzerDialog::Accepted) return;

    m_fileinfo = QFileInfo(filepath);
    this->loadDisassemblerDocks(ctx);
}

void DisassemblerHooks::setTabBarVisible(bool b)
{
    auto* tabbar = m_mainwindow->findChild<QTabBar*>();
    if(tabbar) tabbar->setVisible(b);
}

void DisassemblerHooks::showWelcome()
{
    DisassemblerHooks::tabify(new WelcomeWidget(), KDDockWidgets::DockWidget::Option_NotClosable);
}

void DisassemblerHooks::loadRecents()
{
    QMenu* mnurecents = m_mainwindow->findChild<QMenu*>(HOOK_ACTION_RECENT_FILES);
    if(!mnurecents) return;

    REDasmSettings settings;
    QStringList recents = settings.recentFiles();
    mnurecents->setEnabled(!recents.empty());

    for(int i = 0; i < MAX_RECENT_FILES; i++)
    {
        if(i >= recents.length())
        {
            QAction* action = mnurecents->addAction(QString());
            action->setVisible(false);
            continue;
        }

        if(!QFileInfo().exists(recents[i])) continue;

        QAction* action = mnurecents->addAction(QString("%1 - %2").arg(i).arg(recents[i]));
        action->setData(recents[i]);

        connect(action, &QAction::triggered, this, [=]() {
            this->load(action->data().toString());
        });
    }
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

bool DisassemblerHooks::isLoaded() const { return m_disassemblerdocks != nullptr; }

QAction* DisassemblerHooks::addWindowAction(DockWidget* dw)
{
    if(!dw || !m_mnuwindow || m_windowactions.size() == MAX_WINDOW_ACTIONS) return nullptr;

    QAction* act = m_mnuwindow->addAction(dw->uniqueName());
    connect(act, &QAction::triggered, dw, &DockWidget::raise);

    m_windowactions.push_back(act);
    this->reshortcutWindow();
    return act;
}

void DisassemblerHooks::removeWindowAction(QAction* a)
{
    if(!a || !m_mnuwindow) return;
    m_windowactions.removeOne(a);
    m_mnuwindow->removeAction(a);
    this->reshortcutWindow();
}

OutputWidget* DisassemblerHooks::outputWidget() const { return m_dockoutput ? static_cast<OutputWidget*>(m_dockoutput->widget()) : nullptr; }

void DisassemblerHooks::reshortcutWindow()
{
    for(int i = 0; i < m_windowactions.size(); i++)
        m_windowactions[i]->setShortcut(QKeySequence(QString("ALT+%1").arg(i)));
}

void DisassemblerHooks::checkListingMode()
{
    if(RDContext_HasFlag(this->activeContext().get(), ContextFlags_ShowRDIL)) m_pbrenderer->setText("RDIL");
    else m_pbrenderer->setText("Listing");
}

void DisassemblerHooks::showOutput()
{
    m_dockoutput = DisassemblerHooks::dockify(new OutputWidget(m_mainwindow), KDDockWidgets::DockWidget::Option_NotClosable);
    m_mainwindow->addDockWidget(m_dockoutput, KDDockWidgets::Location_OnBottom);
}

void DisassemblerHooks::close(bool showwelcome)
{
    this->enableViewCommands(false);
    this->enableCommands(nullptr);

    if(m_devdialog) m_devdialog->deleteLater();
    m_devdialog = nullptr;

    auto docks = m_mainwindow->findChildren<KDDockWidgets::DockWidget*>(QString(), Qt::FindChildrenRecursively);

    std::for_each(docks.begin(), docks.end(), [](KDDockWidgets::DockWidget* dw) {
        if(dynamic_cast<OutputWidget*>(dw->widget())) return;
        dw->deleteLater();
    });

    if(showwelcome) this->showWelcome(); // Replaces central widget, if any
    if(m_disassemblerdocks) m_disassemblerdocks->deleteLater();
    m_disassemblerdocks = nullptr;
}

const DisassemblerDocks* DisassemblerHooks::docks() { return DisassemblerHooks::instance()->m_disassemblerdocks; }

void DisassemblerHooks::showDialog(const QString& title, QWidget* w)
{
    QVBoxLayout* l = new QVBoxLayout();
    l->setSpacing(0);
    l->setMargin(0);
    l->addWidget(w);

    QDialog* dialog = new QDialog();
    dialog->setWindowTitle(title);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setLayout(l);
    dialog->resize(DEFAULT_DIALOG_WIDTH, DEFAULT_DIALOG_HEIGHT);
    dialog->show();
}

void DisassemblerHooks::clearOutput()
{
    OutputWidget* outputwidget = this->outputWidget();
    if(outputwidget) outputwidget->clear();
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

void DisassemblerHooks::openHomePage() const { QDesktopServices::openUrl(QUrl("https://redasm.io")); }
void DisassemblerHooks::openTwitter() const { QDesktopServices::openUrl(QUrl("https://twitter.com/re_dasm")); }
void DisassemblerHooks::openTelegram() const { QDesktopServices::openUrl(QUrl("https://t.me/REDasmDisassembler")); }
void DisassemblerHooks::openReddit() const {  QDesktopServices::openUrl(QUrl("https://www.reddit.com/r/REDasm")); }
void DisassemblerHooks::openGitHub() const { QDesktopServices::openUrl(QUrl("https://github.com/REDasmOrg/REDasm/issues")); }

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
    if(!m_disassemblerdocks)
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
    qDebug() << w;

    QAction* actdevtools = m_mainwindow->findChild<QAction*>(HOOK_ACTION_DEVTOOLS);
    QAction* actflc = m_mainwindow->findChild<QAction*>(HOOK_ACTION_FLC);
    auto actions = m_toolbar->actions();

    if(!w)
    {
        for(int i = 2; i < actions.size(); i++)
            actions[i]->setVisible(false);

        actdevtools->setVisible(false);
        actflc->setVisible(false);
        m_pbrenderer->setVisible(false);
        return;
    }

    auto* listingview = dynamic_cast<ListingView*>(w);
    if(m_disassemblerdocks) this->checkListingMode();

    m_pbrenderer->setVisible(listingview);
    actdevtools->setVisible(listingview);
    actflc->setVisible(listingview);
}
