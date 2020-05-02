#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "redasmfonts.h"
#include "redasmsettings.h"
#include "hooks/disassemblerhooks.h"
#include "widgets/disassemblerview.h"
#include "dialogs/signaturesdialog/signaturesdialog.h"
#include "dialogs/problemsdialog/problemsdialog.h"
#include "ui/redasmui.h"
#include "themeprovider.h"
#include <QMessageBox>
#include <QtGui>
#include <rdapi/rdapi.h>
#include <rdapi/support.h>

#define PLUGINS_FOLDER_NAME "plugins"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->action_Open->setIcon(FA_ICON(0xf07c));
    ui->action_Save->setIcon(FA_ICON(0xf0c7));
    ui->action_Back->setIcon(FA_ICON(0xf053));
    ui->action_Forward->setIcon(FA_ICON(0xf054));
    ui->action_Goto->setIcon(FA_ICON(0xf1e5));
    ui->action_Filter->setIcon(FA_ICON(0xf0b0));

    this->setDockNestingEnabled(true);
    this->setTabPosition(Qt::TopDockWidgetArea, QTabWidget::North);
    DisassemblerHooks::initialize(this);

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
    m_pbproblems->setFixedHeight(ui->statusBar->height() * 0.8);
    m_pbproblems->setVisible(false);
    m_pbproblems->setFlat(true);

    ui->statusBar->addPermanentWidget(m_lblstatus, 70);
    ui->statusBar->addPermanentWidget(m_lblprogress, 30);
    ui->statusBar->addPermanentWidget(m_pbproblems);
    ui->statusBar->addPermanentWidget(m_lblstatusicon);

    this->initializeLibrary();
    this->setAcceptDrops(true);
    this->loadWindowState();
    this->checkCommandLine();

    connect(ui->action_Open, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::open);
    connect(ui->action_Save, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::save);
    connect(ui->action_Save_As, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::saveAs);
    connect(ui->action_Close, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::close);
    connect(ui->action_Settings, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::settings);
    connect(ui->action_Blocks, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::showDevBlocks);
    connect(ui->action_Graphs, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::showDevGraphs);
    connect(ui->action_Reset_Layout, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::resetLayout);
    connect(ui->action_About, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::about);
    connect(ui->action_Exit, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::exit);
    connect(m_pbproblems, &QPushButton::clicked, this, &MainWindow::showProblems);
}

MainWindow::~MainWindow()
{
    //r_pm->shutdown();
    delete ui;
}

void MainWindow::closeEvent(QCloseEvent *e)
{
    if(!this->canClose())
    {
        e->ignore();
        return;
    }

    DisassemblerHooks::instance()->close();
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

void MainWindow::onSaveClicked()
{
    // DisassemblerView* currdv = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());
    // if(!currdv) return;

    // REDasm::String rdbfile = Convert::to_rstring(QString("%1.%2").arg(m_fileinfo.baseName(), RDB_SIGNATURE_EXT));
    // r_ctx->log("Saving Database " + rdbfile.quoted());

    //if(!REDasm::Database::save(currdv->disassembler(), rdbfile, Convert::to_rstring(m_fileinfo.fileName())))
        //r_ctx->log(REDasm::Database::lastError());
}

void MainWindow::onSaveAsClicked() // TODO: Handle multiple outputs
{
    // QString s = QFileDialog::getSaveFileName(this, "Save As...", m_fileinfo.fileName(), "REDasm Database (*.rdb)");
    // if(s.isEmpty()) return;

    // DisassemblerView* currdv = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());
    // if(!currdv) return;

    //if(!REDasm::Database::save(currdv->disassembler(), Convert::to_rstring(s), Convert::to_rstring(m_fileinfo.fileName())))
        //r_ctx->log(REDasm::Database::lastError());
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
    //this->setViewWidgetsVisible(this->currentDisassembler());
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
    if(this->findChild<DisassemblerView*>(QString()))
    {
        QMessageBox msgbox(this);
        msgbox.setWindowTitle("Closing");
        msgbox.setText("Are you sure?");
        msgbox.setStandardButtons(QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel);

        if(msgbox.exec() != QMessageBox::Yes)
            return false;
    }

    // this->setViewWidgetsVisible(false);
    // REDasmSettings settings;
    // settings.saveState(this);
    return true;
}

void MainWindow::closeFile()
{
    //RDDisassembler* disassembler = nullptr; //this->currentDisassembler();

    // TODO: messageBox for confirmation?
    //if(disassembler)
    //{
        //r_evt::unsubscribe();
        //disassembler->stop();
    //}

    //DisassemblerView* oldview = nullptr; //this->currentDisassemblerView();

    //if(oldview)
    //{
        //ui->stackView->removeWidget(oldview);
        //oldview->hideActions();
        //oldview->deleteLater();
    //}

    //ui->pteOutput->clear();
    //m_tbactions->setActionEnabled(ToolBarActions::Close, false);
    //m_lblstatus->clear();
    //m_lblprogress->setVisible(false);
    //m_lblstatusicon->setVisible(false);
    //m_pbproblems->setVisible(false);
    //m_tbactions->setStandardActionsEnabled(false);
    //this->setViewWidgetsVisible(false);
    //r_ctx->clearProblems();
}

void MainWindow::checkDisassemblerStatus()
{
    // if(!RD_GetDisassembler())
    // {
    //     m_tbactions->setActionEnabled(ToolBarActions::Close, false);
    //     m_lblstatusicon->setVisible(false);
    //     m_pbproblems->setVisible(false);
    //     return;
    // }

    // if(RD_IsBusy())
    // {
    //     this->setWindowTitle(QString("%1 (Working)").arg(m_fileinfo.fileName()));
    //     m_lblstatusicon->setStyleSheet("color: red;");
    // }
    // else
    // {
    //     this->setWindowTitle(m_fileinfo.fileName());
    //     m_lblstatusicon->setStyleSheet("color: green;");
    // }

    //m_lblstatusicon->setVisible(true);
    //m_lblprogress->setVisible(RD_IsBusy());
    //m_pbproblems->setText(QString::number(r_ctx->problemsCount()) + " problem(s)");
    //m_pbproblems->setVisible(!r_disasm->busy() && r_ctx->hasProblems());

    // m_tbactions->setStandardActionsEnabled(!RD_IsBusy());
    // m_tbactions->setDisassemblerActionsEnabled(!RD_IsBusy());
    // m_tbactions->setActionEnabled(ToolBarActions::Close, true);
}

void MainWindow::showProblems() { ProblemsDialog dlgproblems(this); dlgproblems.exec(); }

void MainWindow::initializeLibrary()
{
    RD_SetTempPath(qUtf8Printable(QStandardPaths::writableLocation(QStandardPaths::TempLocation)));
    RD_SetRuntimePath(qUtf8Printable(QDir::currentPath()));
    //ctxsettings.ui = std::make_shared<REDasmUI>(this);

    RD_SetLogCallback([](const char* s, void*) {
        QMetaObject::invokeMethod(DisassemblerHooks::instance(), "log", Qt::QueuedConnection, Q_ARG(QString, QString::fromUtf8(s)));
    }, nullptr);

    RD_SetStatusCallback([](const char* s, void* userdata) {
        QLabel* lblstatus = reinterpret_cast<QLabel*>(userdata);
        QMetaObject::invokeMethod(lblstatus, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::fromUtf8(s)));
    }, m_lblstatus);

    RD_SetProgressCallback([](size_t pending, void* userdata) {
        QLabel* lblprogress = reinterpret_cast<QLabel*>(userdata);
        QMetaObject::invokeMethod(lblprogress, "setText", Qt::QueuedConnection, Q_ARG(QString, QString("%1 state(s) pending").arg(pending)));
    }, m_lblprogress);

    RD_AddPluginPath(qUtf8Printable(QDir(RD_RuntimePath()).absoluteFilePath(PLUGINS_FOLDER_NAME)));

    for(const QString& searchpaths : QStandardPaths::standardLocations(QStandardPaths::AppDataLocation))
        RD_AddPluginPath(qUtf8Printable(QDir(searchpaths).absoluteFilePath(PLUGINS_FOLDER_NAME)));

    RD_SetSync(true); // TODO: Disable
    RD_InitContext();
}
