#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "redasmfonts.h"
#include "redasmsettings.h"
#include "hooks/disassemblerhooks.h"
#include "widgets/disassemblerview.h"
#include "dialogs/signaturesdialog/signaturesdialog.h"
#include "ui/qtui.h"
#include "themeprovider.h"
#include <QMessageBox>
#include <QDebug>
#include <QtGui>
#include <rdapi/rdapi.h>
#include <iostream>

#define PLUGINS_FOLDER_NAME  "plugins"
#define DATABASE_FOLDER_NAME "database"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->action_Open->setIcon(FA_ICON(0xf07c));
    ui->action_Save->setIcon(FA_ICON(0xf0c7));

    this->setDockNestingEnabled(true);
    this->setTabPosition(Qt::TopDockWidgetArea, QTabWidget::North);

    m_lblstatus = new QLabel(this);
    m_lblprogress = new QLabel(this);
    m_lblprogress->setVisible(false);
    m_lblprogress->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    m_lblstatusicon = new QLabel(this);
    m_lblstatusicon->setObjectName(HOOK_STATUS_ICON);
    m_lblstatusicon->setFixedHeight(ui->statusBar->height() * 0.8);
    m_lblstatusicon->setFont(FA_FONT);
    m_lblstatusicon->setText(u8"\uf017");
    m_lblstatusicon->setVisible(false);

    m_pbrenderer = new QPushButton(this);
    m_pbrenderer->setObjectName(HOOK_RENDERER);
    m_pbrenderer->setFixedHeight(ui->statusBar->height() * 0.8);
    m_pbrenderer->setVisible(false);
    m_pbrenderer->setFlat(true);

    m_pbproblems = new QPushButton(this);
    m_pbproblems->setObjectName(HOOK_PROBLEMS);
    m_pbproblems->setFixedHeight(ui->statusBar->height() * 0.8);
    m_pbproblems->setVisible(false);
    m_pbproblems->setFlat(true);

    ui->statusBar->addPermanentWidget(m_lblstatus, 70);
    ui->statusBar->addPermanentWidget(m_lblprogress, 30);
    ui->statusBar->addPermanentWidget(m_pbrenderer);
    ui->statusBar->addPermanentWidget(m_pbproblems);
    ui->statusBar->addPermanentWidget(m_lblstatusicon);

    DisassemblerHooks::initialize(this);
    this->initializeConfig();
    this->setAcceptDrops(true);
    this->loadWindowState();
    this->checkCommandLine();

    connect(ui->action_Open, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::open);
    connect(ui->action_Save, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::save);
    connect(ui->action_Save_As, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::saveAs);
    connect(ui->action_Close, &QAction::triggered, DisassemblerHooks::instance(), qOverload<>(&DisassemblerHooks::close));
    connect(ui->action_Settings, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::settings);
    connect(ui->action_Developer_Tools, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::showDeveloperTools);
    connect(ui->action_Reset_Layout, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::resetLayout);
    connect(ui->action_About, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::about);
    connect(ui->action_Exit, &QAction::triggered, DisassemblerHooks::instance(), &DisassemblerHooks::exit);
}

MainWindow::~MainWindow() { delete ui; }

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
        QMetaObject::invokeMethod(lblprogress, "setText", Qt::QueuedConnection, Q_ARG(QString, QString("%1 state(s) pending").arg(pending)));
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
        std::cout << appdir << std::endl;
        QString appdirqt = QString::fromUtf8(appdir);
        RDConfig_AddDatabasePath(qUtf8Printable(QDir(appdirqt + QDir::separator() + searchpath).absoluteFilePath(DATABASE_FOLDER_NAME)));
        RDConfig_AddPluginPath(qUtf8Printable(QDir(appdirqt + QDir::separator() + searchpath).absoluteFilePath(PLUGINS_FOLDER_NAME)));
    }

    QtUI::initialize();
}
