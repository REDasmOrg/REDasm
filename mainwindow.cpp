#include "mainwindow.h"
#include "redasmfonts.h"
#include "redasmsettings.h"
#include "hooks/disassemblerhooks.h"
#include "widgets/disassemblerdocks.h"
#include "dialogs/signaturesdialog/signaturesdialog.h"
#include "ui/qtui.h"
#include "themeprovider.h"
#include <QtGui>
#include <QMessageBox>
#include <QStatusBar>
#include <QToolBar>
#include <QMenuBar>
#include <QMenu>
#include <rdapi/rdapi.h>

#define PLUGINS_FOLDER_NAME  "plugins"
#define DATABASE_FOLDER_NAME "database"

MainWindow::MainWindow() : KDDockWidgets::MainWindow("MainWindow", KDDockWidgets::MainWindowOption_HasCentralFrame)
{
    this->resize(1300, 650);
    if(ThemeProvider::isDarkTheme()) this->setWindowIcon(QIcon(":/res/logo_dark.png"));
    else this->setWindowIcon(QIcon(":/res/logo.png"));

    this->createFileMenu();
    this->createREDasmMenu();
    this->createWindowMenu();
    this->createHelpMenu();

    auto* statusbar = new QStatusBar(this);
    this->setStatusBar(statusbar);

    auto* toolbar = new QToolBar(this);
    toolbar->setObjectName(HOOK_TOOLBAR);
    toolbar->setMovable(false);
    toolbar->setFloatable(false);
    toolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    toolbar->addAction(FA_ICON(0xf07c), tr("Open"), []() { DisassemblerHooks::instance()->open(); });
    toolbar->addAction(FA_ICON(0xf0c7), tr("Save"), []() { DisassemblerHooks::instance()->save(); });
    this->addToolBar(Qt::ToolBarArea::TopToolBarArea, toolbar);

    m_lblstatus = new QLabel(this);
    m_lblprogress = new QLabel(this);
    m_lblprogress->setVisible(false);
    m_lblprogress->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    m_lblstatusicon = new QLabel(this);
    m_lblstatusicon->setObjectName(HOOK_STATUS_ICON);
    m_lblstatusicon->setFixedHeight(statusbar->height() * 0.8);
    m_lblstatusicon->setFont(FA_FONT);
    m_lblstatusicon->setText(u8"\uf017");
    m_lblstatusicon->setVisible(false);

    m_pbrenderer = new QPushButton(this);
    m_pbrenderer->setObjectName(HOOK_RENDERER);
    m_pbrenderer->setFixedHeight(statusbar->height() * 0.8);
    m_pbrenderer->setVisible(false);
    m_pbrenderer->setFlat(true);

    m_pbproblems = new QPushButton(this);
    m_pbproblems->setObjectName(HOOK_PROBLEMS);
    m_pbproblems->setFixedHeight(statusbar->height() * 0.8);
    m_pbproblems->setVisible(false);
    m_pbproblems->setFlat(true);

    statusbar->addPermanentWidget(m_lblstatus, 70);
    statusbar->addPermanentWidget(m_lblprogress, 30);
    statusbar->addPermanentWidget(m_pbrenderer);
    statusbar->addPermanentWidget(m_pbproblems);
    statusbar->addPermanentWidget(m_lblstatusicon);

    DisassemblerHooks::initialize(this);
    this->initializeConfig();
    this->setAcceptDrops(true);
    this->loadWindowState();
    this->checkCommandLine();
}

void MainWindow::closeEvent(QCloseEvent *e)
{
    if(!this->canClose())
    {
        e->ignore();
        return;
    }

    DisassemblerHooks::instance()->close(false);
    QWidget::closeEvent(e);
}

void MainWindow::dragEnterEvent(QDragEnterEvent *e)
{
    if(!e->mimeData()->hasUrls()) return;
    e->acceptProposedAction();
}

void MainWindow::dragMoveEvent(QDragMoveEvent *e)
{
    if(!e->mimeData()->hasUrls()) return;
    e->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent *e)
{
    const QMimeData* mimedata = e->mimeData();
    if(!mimedata->hasUrls()) return;

    QList<QUrl> urllist = mimedata->urls();
    QString locfile = urllist.first().toLocalFile();

    QFileInfo fi(locfile);
    if(!fi.isFile()) return;

    DisassemblerHooks::instance()->load(locfile);
    e->acceptProposedAction();
}

void MainWindow::onSignaturesClicked()
{
    //SignaturesDialog dlgsignatures(this->currentDisassembler(), this);
    //dlgsignatures.exec();
}

void MainWindow::onResetLayoutClicked()
{
    REDasmSettings settings;
    settings.defaultState(this);
}

void MainWindow::createFileMenu()
{
    auto* mnubar = this->menuBar();

    auto* mnufile = new QMenu(tr("&File"), mnubar);
    auto* actopen = mnufile->addAction(tr("Open"));

    auto* actsave = mnufile->addAction(tr("Save"));

    auto* actsaveas = mnufile->addAction(tr("Save As"));
    actsaveas->setObjectName(HOOK_ACTION_SAVE_AS);

    auto* mnurecents = new QMenu(tr("&Recent Files"), mnubar);
    mnurecents->setObjectName(HOOK_ACTION_RECENT_FILES);
    mnufile->addMenu(mnurecents);

    auto* actclose = mnufile->addAction(tr("Close"));
    actclose->setObjectName(HOOK_ACTION_CLOSE);

    mnufile->addSeparator();
    auto* actexit = mnufile->addAction(tr("Exit"));

    actopen->setIcon(FA_ICON(0xf07c));
    actsave->setIcon(FA_ICON(0xf0c7));
    mnubar->addMenu(mnufile);

    connect(actopen, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::open);
    connect(actsave, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::save);
    connect(actsaveas, &QAction::triggered, DisassemblerHooks::instance(), qOverload<>(&DisassemblerHooks::saveAs));
    connect(actclose, &QAction::triggered, DisassemblerHooks::instance(), qOverload<>(&DisassemblerHooks::close));
    connect(actexit, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::exit);
}

void MainWindow::createREDasmMenu()
{
    auto* mnubar = this->menuBar();
    auto* mnuredasm = new QMenu("&REDasm", mnubar);

    auto* actflc = mnuredasm->addAction(tr("FLC"));
    auto* actdevtools = mnuredasm->addAction(tr("Developer Tools"));
    auto* actdatabase = mnuredasm->addAction(tr("Database"));
    mnuredasm->addSeparator();
    auto* actsettings = mnuredasm->addAction(tr("Settings"));
    mnubar->addMenu(mnuredasm);

    actflc->setShortcut(QKeySequence("CTRL+F"));
    actdevtools->setShortcut(QKeySequence("CTRL+D"));
    actdatabase->setShortcut(QKeySequence("CTRL+B"));
    actflc->setObjectName(HOOK_ACTION_FLC);
    actdevtools->setObjectName(HOOK_ACTION_DEVTOOLS);
    actdatabase->setObjectName(HOOK_ACTION_DATABASE);

    connect(actflc, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::showFLC);
    connect(actdevtools, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::showDeveloperTools);
    connect(actdatabase, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::showDatabase);
    connect(actsettings, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::settings);
}

void MainWindow::createWindowMenu()
{
    auto* mnubar = this->menuBar();
    auto* mnuwindow = new QMenu(tr("&Window"), mnubar);
    mnuwindow->setObjectName(HOOK_MENU_WINDOW);

    mnuwindow->addAction(tr("&Manage Layouts"));
    auto* actresetlayout = mnuwindow->addAction(tr("&Reset Layout"));

    QMenu* mnusubviews = mnuwindow->addMenu(tr("&Open Subviews"));
    mnusubviews->addAction(tr("Listing"), this, []() { if(DisassemblerHooks::docks()) DisassemblerHooks::docks()->showListing(); });
    mnusubviews->addAction(tr("Segments"), this, []() { if(DisassemblerHooks::docks()) DisassemblerHooks::docks()->showSegments(); });
    mnusubviews->addAction(tr("Exports"), this, []() { if(DisassemblerHooks::docks()) DisassemblerHooks::docks()->showExports(); });
    mnusubviews->addAction(tr("Imports"), this, []() { if(DisassemblerHooks::docks()) DisassemblerHooks::docks()->showImports(); });
    mnusubviews->addAction(tr("Strings"), this, []() { if(DisassemblerHooks::docks()) DisassemblerHooks::docks()->showStrings(); });
    mnusubviews->addSeparator();
    mnusubviews->addAction(tr("Functions"), this, []() { if(DisassemblerHooks::docks()) DisassemblerHooks::docks()->showFunctions(); });
    mnusubviews->addAction(tr("Map"), this, []() { if(DisassemblerHooks::docks()) DisassemblerHooks::docks()->showMap(); });

    mnuwindow->addSeparator();
    mnubar->addMenu(mnuwindow);

    connect(actresetlayout, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::resetLayout);
}

void MainWindow::createHelpMenu()
{
    auto* mnubar = this->menuBar();
    auto* mnuhelp = new QMenu("&?", mnubar);

    auto* acttelegram = mnuhelp->addAction(tr("&Telegram"));
    auto* actreddit = mnuhelp->addAction(tr("&Reddit"));
    mnuhelp->addSeparator();
    auto* actgithub = mnuhelp->addAction(tr("Report an &Issue"));
    auto* actabout = mnuhelp->addAction(tr("&About"));
    mnubar->addMenu(mnuhelp);

    connect(acttelegram, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::openTelegram);
    connect(actreddit, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::openReddit);
    connect(actgithub, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::openGitHub);
    connect(actabout, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::about);
}

void MainWindow::loadWindowState()
{
    REDasmSettings settings;
    if(settings.restoreState(this)) return;

    QRect position = this->frameGeometry();
    position.moveCenter(qApp->primaryScreen()->availableGeometry().center());
    this->move(position.topLeft());
}

bool MainWindow::loadDatabase(const QString &filepath)
{
    // REDasm::String filename;
    // REDasm::Disassembler* disassembler = REDasm::Database::load(Convert::to_rstring(filepath), filename);

    // if(!disassembler)
    // {
    //     if(m_fileinfo.suffix() == RDB_SIGNATURE_EXT)
    //         r_ctx->log(REDasm::Database::lastError());

    //     return false;
    // }

    //r_ctx->log("Selected loader " + REDasm::String(disassembler->loader()->description()).quoted() + " with " +
                                    //REDasm::String(disassembler->assembler()->description()).quoted() + " instruction set");

    //m_fileinfo = QFileInfo(Convert::to_qstring(filename));
    //this->showDisassemblerView(disassembler);
    return true;
}

void MainWindow::checkCommandLine()
{
    QStringList args = qApp->arguments();
    if(args.length() <= 1) return;

    args = args.mid(1); // Skip REDasm's path

    for(const QString& arg : args)
    {
        QFileInfo fileinfo(arg);

        if(!fileinfo.exists() || !fileinfo.isFile() || !fileinfo.isReadable())
            continue;

        DisassemblerHooks::instance()->load(arg);
        break;
    }
}

bool MainWindow::canClose()
{
    if(DisassemblerHooks::instance()->isLoaded())
    {
        QMessageBox msgbox(this);
        msgbox.setWindowTitle(tr("Closing"));
        msgbox.setText(tr("Are you sure?"));
        msgbox.setStandardButtons(QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel);

        if(msgbox.exec() != QMessageBox::Yes)
            return false;
    }

    // REDasmSettings settings;
    // settings.saveState(this);
    return true;
}

void MainWindow::initializeConfig()
{
    RDConfig_SetLogCallback([](const char* s, void*) {
        QMetaObject::invokeMethod(DisassemblerHooks::instance(), "log", Qt::QueuedConnection, Q_ARG(QString, QString::fromUtf8(s)));
    }, nullptr);

    RDConfig_SetStatusCallback([](const char* s, void* userdata) {
        QLabel* lblstatus = reinterpret_cast<QLabel*>(userdata);
        QMetaObject::invokeMethod(lblstatus, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::fromUtf8(s)));
    }, m_lblstatus);

    RDConfig_SetProgressCallback([](size_t pending, void* userdata) {
        QLabel* lblprogress = reinterpret_cast<QLabel*>(userdata);
        QMetaObject::invokeMethod(lblprogress, "setText", Qt::QueuedConnection, Q_ARG(QString, tr("%1 state(s) pending").arg(pending)));
    }, m_lblprogress);

    RDConfig_AddDatabasePath(qUtf8Printable(QDir(RDConfig_GetRuntimePath()).absoluteFilePath(DATABASE_FOLDER_NAME)));
    RDConfig_AddPluginPath(qUtf8Printable(QDir(RDConfig_GetRuntimePath()).absoluteFilePath(PLUGINS_FOLDER_NAME)));

    const char* appdir = std::getenv("APPDIR");
    bool isappimage = appdir && std::getenv("APPIMAGE");

    for(const QString& searchpath : QStandardPaths::standardLocations(QStandardPaths::AppDataLocation))
    {
        RDConfig_AddDatabasePath(qUtf8Printable(QDir(searchpath).absoluteFilePath(DATABASE_FOLDER_NAME)));
        RDConfig_AddPluginPath(qUtf8Printable(QDir(searchpath).absoluteFilePath(PLUGINS_FOLDER_NAME)));

        if(!isappimage) continue;
        QString appdirqt = QString::fromUtf8(appdir);

        RDConfig_AddDatabasePath(qUtf8Printable(QDir(appdirqt + QDir::separator() + searchpath).absoluteFilePath(DATABASE_FOLDER_NAME)));
        RDConfig_AddPluginPath(qUtf8Printable(QDir(appdirqt + QDir::separator() + searchpath).absoluteFilePath(PLUGINS_FOLDER_NAME)));
    }

    QtUI::initialize();
}
