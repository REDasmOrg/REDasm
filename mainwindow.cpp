#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "dialogs/signaturesdialog/signaturesdialog.h"
#include "dialogs/problemsdialog/problemsdialog.h"
#include "dialogs/settingsdialog/settingsdialog.h"
#include "dialogs/aboutdialog/aboutdialog.h"
#include "ui/redasmui.h"
#include "redasmsettings.h"
#include "themeprovider.h"
#include "convert.h"
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/plugins/pluginmanager.h>
#include <redasm/support/utils.h>
#include <QtWidgets>
#include <QtCore>
#include <QtGui>

#define PLUGINS_FOLDER_NAME "plugins"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->toolBar->actions()[3]->setVisible(false); // Hide separator
    this->tabifyDockWidget(ui->dockFunctions, ui->dockCallTree);

    REDasm::ContextSettings ctxsettings;
    ctxsettings.tempPath = Convert::to_rstring(QStandardPaths::writableLocation(QStandardPaths::TempLocation));
    ctxsettings.runtimePath = Convert::to_rstring(QDir::currentPath());
    ctxsettings.statusCallback = [&](const REDasm::String& s) { QMetaObject::invokeMethod(m_lblstatus, "setText", Qt::QueuedConnection, Q_ARG(QString, S_TO_QS(s))); };
    ctxsettings.progressCallback = [&](size_t pending) { QMetaObject::invokeMethod(m_lblprogress, "setText", Qt::QueuedConnection, Q_ARG(QString, QString("%1 state(s) pending").arg(pending))); };
    ctxsettings.logCallback = [&](const REDasm::String& s) { QMetaObject::invokeMethod(ui->pteOutput, "log", Qt::QueuedConnection, Q_ARG(QString, Convert::to_qstring(s))); };
    ctxsettings.ui = std::make_shared<REDasmUI>(this);

    for(const QString& searchpaths : QStandardPaths::standardLocations(QStandardPaths::AppDataLocation))
        ctxsettings.pluginPaths.push_back(REDasm::Path::create(Convert::to_rstring(searchpaths), PLUGINS_FOLDER_NAME));

#ifdef REDASM_PORTABLE_MODE
    ctxsettings.pluginPaths.push_front(REDasm::Path::create(ctxsettings.runtimePath, PLUGINS_FOLDER_NAME));
#endif

    REDasm::Context::init(ctxsettings);
    this->setViewWidgetsVisible(false);
    ui->leFilter->setVisible(false);

    ui->action_Open->setIcon(THEME_ICON("open"));
    ui->action_Save->setIcon(THEME_ICON("save"));
    ui->action_Signatures->setIcon(THEME_ICON("database"));

    m_lblstatus = new QLabel(this);
    m_lblprogress = new QLabel(this);
    m_lblprogress->setVisible(false);
    m_lblprogress->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    m_pbstatus = new QPushButton(this);
    m_pbstatus->setFlat(true);
    m_pbstatus->setFixedWidth(ui->statusBar->height() * 0.8);
    m_pbstatus->setFixedHeight(ui->statusBar->height() * 0.8);
    m_pbstatus->setText(QString::fromWCharArray(L"\u25cf"));
    m_pbstatus->setVisible(false);

    m_pbproblems = new QPushButton(this);
    m_pbproblems->setFlat(true);
    m_pbproblems->setFixedHeight(ui->statusBar->height() * 0.8);
    m_pbproblems->setVisible(false);

    ui->statusBar->addPermanentWidget(m_lblstatus, 70);
    ui->statusBar->addPermanentWidget(m_lblprogress, 30);
    ui->statusBar->addPermanentWidget(m_pbproblems);
    ui->statusBar->addPermanentWidget(m_pbstatus);

    this->setAcceptDrops(true);
    this->loadWindowState();
    this->loadRecents();
    this->checkCommandLine();

    connect(ui->action_Open, &QAction::triggered, this, &MainWindow::onOpenClicked);
    connect(ui->action_Save, &QAction::triggered, this, &MainWindow::onSaveClicked);
    connect(ui->action_Save_As, &QAction::triggered, this, &MainWindow::onSaveAsClicked);
    connect(ui->action_Close, &QAction::triggered, this, &MainWindow::closeFile);
    connect(ui->action_Exit, &QAction::triggered, this, &MainWindow::onExitClicked);
    connect(ui->action_Signatures, &QAction::triggered, this, &MainWindow::onSignaturesClicked);
    connect(ui->action_Reset_Layout, &QAction::triggered, this, &MainWindow::onResetLayoutClicked);
    connect(ui->action_Settings, &QAction::triggered, this, &MainWindow::onSettingsClicked);
    connect(ui->action_About_REDasm, &QAction::triggered, this, &MainWindow::onAboutClicked);

    connect(ui->action_Report_Bug, &QAction::triggered, this, []() {
        QDesktopServices::openUrl(QUrl("https://github.com/REDasmOrg/REDasm/issues"));
    });

    connect(ui->action_Subscribe_to_r_REDasm, &QAction::triggered, this, []() {
        QDesktopServices::openUrl(QUrl("https://www.reddit.com/r/REDasm"));
    });

    connect(m_pbstatus, &QPushButton::clicked, this, &MainWindow::changeDisassemblerStatus);
    connect(m_pbproblems, &QPushButton::clicked, this, &MainWindow::showProblems);

    qApp->installEventFilter(this);
}

MainWindow::~MainWindow() { delete ui; }

void MainWindow::closeEvent(QCloseEvent *e)
{
    if(!this->canClose())
    {
        e->ignore();
        return;
    }

    this->closeFile(); // Deallocate actions and docks
    QWidget::closeEvent(e);
}

void MainWindow::dragEnterEvent(QDragEnterEvent *e)
{
    if(!e->mimeData()->hasUrls())
        return;

    e->acceptProposedAction();
}

void MainWindow::dragMoveEvent(QDragMoveEvent *e)
{
    if(!e->mimeData()->hasUrls())
        return;

    e->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent *e)
{
    const QMimeData* mimedata = e->mimeData();

    if(!mimedata->hasUrls())
        return;

      QList<QUrl> urllist = mimedata->urls();
      QString locfile = urllist.first().toLocalFile();
      QFileInfo fi(locfile);

      if(!fi.isFile())
          return;

      this->load(locfile);
      e->acceptProposedAction();
}

bool MainWindow::eventFilter(QObject *obj, QEvent *e)
{
    DisassemblerView* disassemblerview = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());

    if(disassemblerview && !disassemblerview->disassembler()->busy())
    {
        if(e->type() == QEvent::KeyPress)
        {
            QKeyEvent* keyevent = static_cast<QKeyEvent*>(e);

            if(ui->leFilter->isVisible() && keyevent->matches(QKeySequence::Cancel))
            {
                disassemblerview->clearFilter();
                return true;
            }
            else if(keyevent->key() == Qt::Key_F3)
            {
                disassemblerview->toggleFilter();
                return true;
            }
        }
    }

    return QMainWindow::eventFilter(obj, e);
}

void MainWindow::onOpenClicked()
{
    QString s = QFileDialog::getOpenFileName(this, "Disassemble file...");

    if(s.isEmpty())
        return;

    this->load(s);
}

void MainWindow::onSaveClicked()
{
    DisassemblerView* currdv = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());

    if(!currdv)
        return;

    REDasm::String rdbfile = Convert::to_rstring(QString("%1.%2").arg(m_fileinfo.baseName(), RDB_SIGNATURE_EXT));
    r_ctx->log("Saving Database " + rdbfile.quoted());

    if(!REDasm::Database::save(currdv->disassembler(), rdbfile, Convert::to_rstring(m_fileinfo.fileName())))
        r_ctx->log(REDasm::Database::lastError());
}

void MainWindow::onSaveAsClicked() // TODO: Handle multiple outputs
{
    QString s = QFileDialog::getSaveFileName(this, "Save As...", m_fileinfo.fileName(), "REDasm Database (*.rdb)");

    if(s.isEmpty())
        return;

    DisassemblerView* currdv = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());

    if(!currdv)
        return;

    if(!REDasm::Database::save(currdv->disassembler(), Convert::to_rstring(s), Convert::to_rstring(m_fileinfo.fileName())))
        r_ctx->log(REDasm::Database::lastError());
}

void MainWindow::onRecentFileClicked()
{
    QAction* sender = qobject_cast<QAction*>(this->sender());

    if(sender)
        this->load(sender->data().toString());
}

void MainWindow::onExitClicked()
{
    if(!this->canClose())
        return;

    qApp->exit();
}

void MainWindow::onSignaturesClicked()
{
    SignaturesDialog dlgsignatures(this->currentDisassembler(), this);
    dlgsignatures.exec();
}

void MainWindow::onResetLayoutClicked()
{
    REDasmSettings settings;
    settings.defaultState(this);
    this->setViewWidgetsVisible(this->currentDisassembler());
}

void MainWindow::onSettingsClicked()
{
    SettingsDialog sd(this);
    sd.exec();
}

void MainWindow::loadWindowState()
{
    REDasmSettings settings;

    if(settings.restoreState(this))
        return;

    QRect position = this->frameGeometry();
    position.moveCenter(qApp->primaryScreen()->availableGeometry().center());
    this->move(position.topLeft());
}

void MainWindow::loadRecents()
{
    REDasmSettings settings;
    m_recents = settings.recentFiles();
    ui->action_Recent_Files->setEnabled(!m_recents.empty());

    QMenu* mnurecents = ui->action_Recent_Files->menu();

    if(!mnurecents)
    {
        mnurecents = new QMenu(this);
        ui->action_Recent_Files->setMenu(mnurecents);
    }
    else
        mnurecents->clear();

    for(int i = 0; i < MAX_RECENT_FILES; i++)
    {
        if(i >= m_recents.length())
        {
            QAction* action = mnurecents->addAction(QString());
            action->setVisible(false);
            continue;
        }

        if(!QFileInfo(m_recents[i]).exists())
            continue;

        QAction* action = mnurecents->addAction(QString("%1 - %2").arg(i).arg(m_recents[i]));
        action->setData(m_recents[i]);
        connect(action, &QAction::triggered, this, &MainWindow::onRecentFileClicked);
    }
}

bool MainWindow::loadDatabase(const QString &filepath)
{
    REDasm::String filename;
    REDasm::Disassembler* disassembler = REDasm::Database::load(Convert::to_rstring(filepath), filename);

    if(!disassembler)
    {
        if(m_fileinfo.suffix() == RDB_SIGNATURE_EXT)
            r_ctx->log(REDasm::Database::lastError());

        return false;
    }

    r_ctx->log("Selected loader " + REDasm::String(disassembler->loader()->description()).quoted() + " with " +
                                    REDasm::String(disassembler->assembler()->description()).quoted() + " instruction set");

    m_fileinfo = QFileInfo(Convert::to_qstring(filename));
    this->showDisassemblerView(disassembler, true);
    return true;
}

void MainWindow::load(const QString& filepath)
{
    this->closeFile();

    m_fileinfo = QFileInfo(filepath);
    QDir::setCurrent(m_fileinfo.path());

    REDasmSettings settings;
    settings.updateRecentFiles(filepath);
    this->loadRecents();

    if(this->loadDatabase(filepath))
        return;

    REDasm::MemoryBuffer* buffer = REDasm::MemoryBuffer::fromFile(Convert::to_rstring(filepath)); // TODO: Deallocate in case of user-cancel?

    if(buffer && !buffer->empty())
    {
        REDasm::LoadRequest request(Convert::to_rstring(filepath), buffer);
        this->selectLoader(request);
    }
}

void MainWindow::checkCommandLine()
{
    QStringList args = qApp->arguments();

    if(args.length() <= 1)
        return;

    args = args.mid(1); // Skip REDasm's path

    for(const QString& arg : args)
    {
        QFileInfo fileinfo(arg);

        if(!fileinfo.exists() || !fileinfo.isFile() || !fileinfo.isReadable())
            continue;

        this->load(arg);
        break;
    }
}

void MainWindow::setStandardActionsEnabled(bool b)
{
    ui->action_Save->setEnabled(b);
    ui->action_Save_As->setEnabled(b);
    ui->action_Signatures->setEnabled(b);
}

void MainWindow::showDisassemblerView(REDasm::Disassembler *disassembler, bool fromdatabase)
{
    EVENT_CONNECT(disassembler, busyChanged, this, [&]() {
        QMetaObject::invokeMethod(this, "checkDisassemblerStatus", Qt::QueuedConnection);
    });

    ui->pteOutput->clear();

    QWidget* oldwidget = ui->stackView->widget(0);

    if(oldwidget)
    {
        ui->stackView->removeWidget(oldwidget);
        oldwidget->deleteLater();
    }

    DisassemblerView *dv = new DisassemblerView(ui->leFilter);
    dv->bindDisassembler(disassembler, fromdatabase); // Take ownership
    ui->stackView->addWidget(dv);

    this->setViewWidgetsVisible(true);
    this->checkDisassemblerStatus();
}

bool MainWindow::canClose()
{
    if(dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget()))
    {
        QMessageBox msgbox(this);
        msgbox.setWindowTitle("Closing");
        msgbox.setText("Are you sure?");
        msgbox.setStandardButtons(QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel);

        if(msgbox.exec() != QMessageBox::Yes)
            return false;
    }

    this->setViewWidgetsVisible(false);
    REDasmSettings settings;
    settings.saveState(this);
    return true;
}

void MainWindow::closeFile()
{
    REDasm::Disassembler* disassembler = this->currentDisassembler();

    // TODO: messageBox for confirmation?
    if(disassembler)
    {
        disassembler->busyChanged.disconnect();
        disassembler->stop();
    }

    DisassemblerView* oldview = this->currentDisassemblerView();

    if(oldview != nullptr)
    {
        oldview->hideActions();
        ui->stackView->removeWidget(oldview);
        oldview->deleteLater();
    }

    ui->action_Close->setEnabled(false);
    ui->pteOutput->clear();
    m_lblstatus->clear();
    m_lblprogress->setVisible(false);
    m_pbstatus->setVisible(false);
    m_pbproblems->setVisible(false);
    this->setStandardActionsEnabled(false);
    this->setViewWidgetsVisible(false);
    r_ctx->clearProblems();
}

void MainWindow::selectLoader(const REDasm::LoadRequest& request)
{
    LoaderDialog dlgloader(request, this);

    if(dlgloader.exec() != LoaderDialog::Accepted)
        return;

    const REDasm::PluginInstance *assemblerpi = nullptr, *loaderpi = dlgloader.selectedLoader();
    REDasm::Loader* loader = plugin_cast<REDasm::Loader>(loaderpi);

    if(loader->flags() & REDasm::LoaderFlags::CustomAssembler)
        assemblerpi = dlgloader.selectedAssembler();
    else
        assemblerpi = r_pm->findAssembler(loader->assembler());

    if(!assemblerpi)
    {
        QMessageBox::information(this, "Assembler not found", QString("Cannot find assembler '%1'").arg(QString::fromUtf8(loader->assembler())));

        connect(&dlgloader, &LoaderDialog::destroyed, this, [loader]() {
            r_pm->unload(loader->instance());
        });

        return;
    }

    REDasm::Assembler* assembler = plugin_cast<REDasm::Assembler>(assemblerpi);
    assembler->init(loader->assembler());

    if(loader->flags() & REDasm::LoaderFlags::CustomAddressing)
        loader->build(assembler->id(), dlgloader.offset(), dlgloader.baseAddress(), dlgloader.entryPoint());
    else
        loader->load();

    r_ctx->log("Selected loader " + REDasm::String(loader->description()).quoted() +
               " with " + REDasm::String(assembler->description()).quoted() + " instruction set");

    REDasm::Disassembler* disassembler = new REDasm::Disassembler(assembler, loader);

    EVENT_CONNECT(disassembler, busyChanged, this, [&]() {
        DisassemblerView* currdv = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());

        if(currdv)
            QMetaObject::invokeMethod(m_lblprogress, "setVisible", Qt::QueuedConnection, Q_ARG(bool, currdv->disassembler()->busy()));
    });

    this->showDisassemblerView(disassembler, false); // Take ownership
}

void MainWindow::setViewWidgetsVisible(bool b)
{
    ui->dockFunctions->setVisible(b);
    ui->dockCallTree->setVisible(b);
    ui->dockReferences->setVisible(b);
    ui->dockListingMap->setVisible(b);
}

void MainWindow::onAboutClicked()
{
    AboutDialog dlgabout(this);
    dlgabout.exec();
}

void MainWindow::changeDisassemblerStatus()
{
    REDasm::Disassembler* disassembler = this->currentDisassembler();

    if(!disassembler)
        return;

    if(disassembler->state() == REDasm::JobState::ActiveState)
        disassembler->pause();
    else if(disassembler->state() == REDasm::JobState::PausedState)
        disassembler->resume();
}

void MainWindow::checkDisassemblerStatus()
{
    REDasm::Disassembler* disassembler = this->currentDisassembler();

    if(!disassembler)
    {
        ui->action_Close->setEnabled(false);
        m_pbstatus->setVisible(false);
        m_pbproblems->setVisible(false);
        return;
    }

    this->setWindowTitle(disassembler->busy() ? QString("%1 (Working)").arg(m_fileinfo.fileName()) : m_fileinfo.fileName());
    REDasm::JobState state = disassembler->state();

    if(state == REDasm::JobState::ActiveState)
        m_pbstatus->setStyleSheet("color: red;");
    else if(state == REDasm::JobState::PausedState)
        m_pbstatus->setStyleSheet("color: goldenrod;");
    else
        m_pbstatus->setStyleSheet("color: green;");

    m_pbstatus->setVisible(true);
    m_lblprogress->setVisible(disassembler->busy());
    m_pbproblems->setText(QString::number(r_ctx->problemsCount()) + " problem(s)");
    m_pbproblems->setVisible(!disassembler->busy() && r_ctx->hasProblems());

    this->setStandardActionsEnabled(!disassembler->busy());
    ui->action_Close->setEnabled(true);
}

void MainWindow::showProblems()
{
    ProblemsDialog dlgproblems(this);
    dlgproblems.exec();
}

DisassemblerView *MainWindow::currentDisassemblerView() const { return dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget()); }

REDasm::Disassembler *MainWindow::currentDisassembler() const
{
    DisassemblerView* currdv = this->currentDisassemblerView();

    if(!currdv)
        return nullptr;

    return currdv->disassembler();
}
