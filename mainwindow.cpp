#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "dialogs/signaturesdialog/signaturesdialog.h"
#include "dialogs/problemsdialog/problemsdialog.h"
#include "dialogs/settingsdialog/settingsdialog.h"
#include "dialogs/aboutdialog/aboutdialog.h"
#include "dialogs/tabledialog/tabledialog.h"
#include "dialogs/dev/functiongraphdialog/functiongraphdialog.h"
#include "models/dev/blocklistmodel.h"
#include "ui/redasmui.h"
#include "redasmfonts.h"
#include "redasmsettings.h"
#include "themeprovider.h"
#include "convert.h"
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/plugins/pluginmanager.h>
#include <redasm/support/filesystem.h>
#include <QtConcurrent/QtConcurrent>
#include <QFutureWatcher>
#include <QtWidgets>
#include <QtCore>
#include <QtGui>

#define PLUGINS_FOLDER_NAME "plugins"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->dockListingMap->setTitleBarWidget(new QWidget());
    m_tbactions = new ToolBarActions(this);

    this->tabifyDockWidget(ui->dockFunctions, ui->dockCallTree);

    REDasm::ContextSettings ctxsettings;
    ctxsettings.tempPath = Convert::to_rstring(QStandardPaths::writableLocation(QStandardPaths::TempLocation));
    ctxsettings.runtimePath = Convert::to_rstring(QDir::currentPath());
    ctxsettings.statusCallback = [&](const REDasm::String& s) { QMetaObject::invokeMethod(m_lblstatus, "setText", Qt::QueuedConnection, Q_ARG(QString, Convert::to_qstring(s))); };
    ctxsettings.progressCallback = [&](size_t pending) { QMetaObject::invokeMethod(m_lblprogress, "setText", Qt::QueuedConnection, Q_ARG(QString, QString("%1 state(s) pending").arg(pending))); };
    ctxsettings.logCallback = [&](const REDasm::String& s) { QMetaObject::invokeMethod(ui->pteOutput, "log", Qt::QueuedConnection, Q_ARG(QString, Convert::to_qstring(s))); };
    ctxsettings.ui = std::make_shared<REDasmUI>(this);

    REDasm::Context::init(ctxsettings);
    r_ctx->addPluginPath(REDasm::FS::Path::join(ctxsettings.runtimePath, PLUGINS_FOLDER_NAME));

    for(const QString& searchpaths : QStandardPaths::standardLocations(QStandardPaths::AppDataLocation))
        r_ctx->addPluginPath(REDasm::FS::Path::join(Convert::to_rstring(searchpaths), PLUGINS_FOLDER_NAME));

    //r_ctx->sync(true);
    this->setViewWidgetsVisible(false);
    ui->leFilter->setVisible(false);

    m_lblstatus = new QLabel(this);
    m_lblprogress = new QLabel(this);
    m_lblprogress->setVisible(false);
    m_lblprogress->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    m_lblstatusicon = new QLabel(this);
    m_lblstatusicon->setFixedHeight(ui->statusBar->height() * 0.8);
    m_lblstatusicon->setFont(FA_FONT);
    m_lblstatusicon->setText("\uf017");
    m_lblstatusicon->setVisible(false);

    m_pbproblems = new QPushButton(this);
    m_pbproblems->setFlat(true);
    m_pbproblems->setFixedHeight(ui->statusBar->height() * 0.8);
    m_pbproblems->setVisible(false);

    ui->statusBar->addPermanentWidget(m_lblstatus, 70);
    ui->statusBar->addPermanentWidget(m_lblprogress, 30);
    ui->statusBar->addPermanentWidget(m_pbproblems);
    ui->statusBar->addPermanentWidget(m_lblstatusicon);

    this->setAcceptDrops(true);
    this->loadWindowState();
    this->checkCommandLine();

    connect(m_tbactions, &ToolBarActions::open, this, &MainWindow::onOpenClicked);
    connect(m_tbactions, &ToolBarActions::save, this, &MainWindow::onSaveClicked);
    connect(m_tbactions, &ToolBarActions::saveAs, this, &MainWindow::onSaveAsClicked);
    connect(m_tbactions, &ToolBarActions::close, this, &MainWindow::closeFile);
    connect(m_tbactions, &ToolBarActions::exit, this, &MainWindow::onExitClicked);
    connect(m_tbactions, &ToolBarActions::signatures, this, &MainWindow::onSignaturesClicked);
    connect(m_tbactions, &ToolBarActions::resetLayout, this, &MainWindow::onResetLayoutClicked);
    connect(m_tbactions, &ToolBarActions::settings, this, &MainWindow::onSettingsClicked);
    connect(m_tbactions, &ToolBarActions::blocks, this, &MainWindow::onBlocksClicked);
    connect(m_tbactions, &ToolBarActions::functionGraphs, this, &MainWindow::onFunctionGraphsClicked);
    connect(m_tbactions, &ToolBarActions::about, this, &MainWindow::onAboutClicked);
    connect(m_tbactions, &ToolBarActions::loadRecent, this, &MainWindow::load);

    connect(m_pbproblems, &QPushButton::clicked, this, &MainWindow::showProblems);
    qApp->installEventFilter(this);
}

MainWindow::~MainWindow()
{
    r_pm->shutdown();
    delete ui;
}

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
    if(s.isEmpty()) return;

    DisassemblerView* currdv = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());
    if(!currdv) return;

    if(!REDasm::Database::save(currdv->disassembler(), Convert::to_rstring(s), Convert::to_rstring(m_fileinfo.fileName())))
        r_ctx->log(REDasm::Database::lastError());
}

void MainWindow::onRecentFileClicked(const QString& filepath)
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

void MainWindow::onBlocksClicked()
{
    if(!this->currentDisassemblerView()) return;
    static TableDialog* td = nullptr;

    if(!td)
    {
        td = new TableDialog(this);
        td->setWindowTitle("Block List");
        td->enableFiltering();
        td->setButtonBoxVisible(false);
        td->setModel(new BlockListModel());
    }

    td->show();
}

void MainWindow::onFunctionGraphsClicked()
{
    FunctionGraphDialog dlggraph(this);
    dlggraph.exec();
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
    this->showDisassemblerView(disassembler);
    return true;
}

void MainWindow::load(const QString& filepath)
{
    this->closeFile();

    m_fileinfo = QFileInfo(filepath);
    QDir::setCurrent(m_fileinfo.path());

    REDasmSettings settings;
    settings.updateRecentFiles(filepath);
    m_tbactions->loadRecents();

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

void MainWindow::showDisassemblerView(REDasm::Disassembler *disassembler)
{
    r_evt::subscribe(REDasm::StandardEvents::Disassembler_BusyChanged, this, [&](const REDasm::EventArgs*) {
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
    connect(m_tbactions, &ToolBarActions::goTo, dv, &DisassemblerView::showGoto);
    connect(m_tbactions, &ToolBarActions::back, dv, &DisassemblerView::goBack);
    connect(m_tbactions, &ToolBarActions::forward, dv, &DisassemblerView::goForward);

    dv->bindDisassembler(disassembler); // Take ownership
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
        r_evt::unsubscribe();
        disassembler->stop();
    }

    DisassemblerView* oldview = this->currentDisassemblerView();

    if(oldview != nullptr)
    {
        oldview->hideActions();
        ui->stackView->removeWidget(oldview);
        oldview->deleteLater();
    }

    m_tbactions->setActionEnabled(ToolBarActions::Close, false);
    ui->pteOutput->clear();
    m_lblstatus->clear();
    m_lblprogress->setVisible(false);
    m_lblstatusicon->setVisible(false);
    m_pbproblems->setVisible(false);
    m_tbactions->setStandardActionsEnabled(false);
    this->setViewWidgetsVisible(false);
    r_ctx->clearProblems();
}

void MainWindow::selectLoader(const REDasm::LoadRequest& request)
{
    LoaderDialog dlgloader(request, this);
    if(dlgloader.exec() != LoaderDialog::Accepted) return;

    const REDasm::PluginInstance *assemblerpi = nullptr, *loaderpi = dlgloader.selectedLoader();
    REDasm::Loader* loader = plugin_cast<REDasm::Loader>(loaderpi);

    if(loader->flags() & REDasm::Loader::CustomAssembler) assemblerpi = dlgloader.selectedAssembler();
    else assemblerpi = r_pm->findAssembler(loader->assembler());

    if(!assemblerpi)
    {
        QString assembler = Convert::to_qstring(loader->assembler());

        QMessageBox::information(this, "Assembler Error",
                                 assembler.isEmpty() ? QString("Assembler not set for '%1'").arg(Convert::to_qstring(loader->descriptor()->description)) :
                                                       QString("Cannot find assembler '%1'").arg(assembler));

        connect(&dlgloader, &LoaderDialog::destroyed, this, [loader]() {
            r_pm->unload(loader->instance());
        });

        return;
    }

    REDasm::Assembler* assembler = plugin_cast<REDasm::Assembler>(assemblerpi);
    assembler->init(loader->assembler());

    r_ctx->log("Selected loader " + REDasm::String(loader->description()).quoted() +
               " with " + REDasm::String(assembler->description()).quoted() + " assembler");

    REDasm::Disassembler* disassembler = new REDasm::Disassembler(assembler, loader);

    r_evt::subscribe(REDasm::StandardEvents::Disassembler_BusyChanged, this, [&](const REDasm::EventArgs*) {
        QMetaObject::invokeMethod(m_lblprogress, "setVisible", Qt::QueuedConnection, Q_ARG(bool, r_disasm->busy()));
    });

    this->showDisassemblerView(disassembler); // Take ownership

    if(r_ldr->flags() & REDasm::Loader::CustomAddressing)
    {
        r_ldr->build(assembler->id(), dlgloader.offset(), dlgloader.baseAddress(), dlgloader.entryPoint());
        this->currentDisassembler()->disassemble();
    }
    else
    {
        auto* futurewatcher = new QFutureWatcher<void>(this);
        connect(futurewatcher, &QFutureWatcher<void>::finished, this, [&]() { this->currentDisassembler()->disassemble(); });
        connect(futurewatcher, &QFutureWatcher<void>::finished, futurewatcher, &QFutureWatcher<void>::deleteLater);
        futurewatcher->setFuture(QtConcurrent::run([&]() { r_ldr->load(); }));
    }
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

void MainWindow::checkDisassemblerStatus()
{
    if(!r_disasm)
    {
        m_tbactions->setActionEnabled(ToolBarActions::Close, false);
        m_lblstatusicon->setVisible(false);
        m_pbproblems->setVisible(false);
        return;
    }

    if(r_disasm->busy())
    {
        this->setWindowTitle(QString("%1 (Working)").arg(m_fileinfo.fileName()));
        m_lblstatusicon->setStyleSheet("color: red;");
    }
    else
    {
        this->setWindowTitle(m_fileinfo.fileName());
        m_lblstatusicon->setStyleSheet("color: green;");
    }

    m_lblstatusicon->setVisible(true);
    m_lblprogress->setVisible(r_disasm->busy());
    m_pbproblems->setText(QString::number(r_ctx->problemsCount()) + " problem(s)");
    m_pbproblems->setVisible(!r_disasm->busy() && r_ctx->hasProblems());

    m_tbactions->setStandardActionsEnabled(!r_disasm->busy());
    m_tbactions->setDisassemblerActionsEnabled(!r_disasm->busy());
    m_tbactions->setActionEnabled(ToolBarActions::Close, true);
}

void MainWindow::showProblems() { ProblemsDialog dlgproblems(this); dlgproblems.exec(); }
DisassemblerView *MainWindow::currentDisassemblerView() const { return dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget()); }

REDasm::Disassembler *MainWindow::currentDisassembler() const
{
    DisassemblerView* currdv = this->currentDisassemblerView();
    return currdv ? currdv->disassembler(): nullptr;
}
