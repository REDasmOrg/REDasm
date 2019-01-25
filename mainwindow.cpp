#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "widgets/disassemblerview/disassemblerview.h"
#include "dialogs/manualloaddialog.h"
#include "dialogs/settingsdialog.h"
#include "dialogs/aboutdialog.h"
#include "redasmsettings.h"
#include "themeprovider.h"
#include <redasm/database/database.h>
#include <QtCore>
#include <QtGui>
#include <QtWidgets>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow), m_disassembler(NULL)
{
    ui->setupUi(this);

    REDasm::setStatusCallback([this](std::string s) {
        QMetaObject::invokeMethod(m_lblstatus, "setText", Qt::QueuedConnection, Q_ARG(QString, S_TO_QS(s)));
    });

    REDasm::setProgressCallback([&](size_t pending) {
        QMetaObject::invokeMethod(m_lblprogress, "setText", Qt::QueuedConnection, Q_ARG(QString, QString("%1 state(s) pending").arg(pending)));
    });

    REDasm::setLoggerCallback([&](const std::string& s) {
        QMetaObject::invokeMethod(ui->pteOutput, "log", Qt::QueuedConnection, Q_ARG(QString, S_TO_QS(s)));
    });

    REDasm::init(QStandardPaths::writableLocation(QStandardPaths::TempLocation).toStdString(),
                 QDir::currentPath().toStdString());

    REDasm::log(QString("REDasm loaded with %1 formats and %2 assemblers").arg(REDasm::Plugins::formats.size())
                                                                          .arg(REDasm::Plugins::assemblers.size()).toStdString());

    this->setViewWidgetsVisible(false);
    ui->leFilter->setVisible(false);

    ui->action_Open->setIcon(THEME_ICON("open"));
    ui->action_Save->setIcon(THEME_ICON("save"));
    ui->action_Import_Signature->setIcon(THEME_ICON("database_import"));

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

    ui->statusBar->addPermanentWidget(m_lblstatus, 70);
    ui->statusBar->addPermanentWidget(m_lblprogress, 30);
    ui->statusBar->addPermanentWidget(m_pbstatus);

    this->setAcceptDrops(true);
    this->loadGeometry();
    this->loadRecents();
    this->checkCommandLine();

    connect(ui->action_Open, &QAction::triggered, this, &MainWindow::onOpenClicked);
    connect(ui->action_Save, &QAction::triggered, this, &MainWindow::onSaveClicked);
    connect(ui->action_Save_As, &QAction::triggered, this, &MainWindow::onSaveAsClicked);
    connect(ui->action_Close, &QAction::triggered, this, &MainWindow::onCloseClicked);
    connect(ui->action_Exit, &QAction::triggered, this, &MainWindow::onExitClicked);
    connect(ui->action_Import_Signature, &QAction::triggered, this, &MainWindow::onImportSignatureClicked);
    connect(ui->action_Settings, &QAction::triggered, this, &MainWindow::onSettingsClicked);
    connect(ui->action_About_REDasm, &QAction::triggered, this, &MainWindow::onAboutClicked);

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

    std::string rdbfile = QString("%1.%2").arg(m_fileinfo.baseName(), RDB_SIGNATURE_EXT).toStdString();
    REDasm::log("Saving Database " + REDasm::quoted(rdbfile));

    if(!REDasm::Database::save(currdv->disassembler(), rdbfile, m_fileinfo.fileName().toStdString()))
        REDasm::log(REDasm::Database::lastError());
}

void MainWindow::onSaveAsClicked() // TODO: Handle multiple outputs
{
    QString s = QFileDialog::getSaveFileName(this, "Save As...", m_fileinfo.fileName(), "REDasm Database (*.rdb)");

    if(s.isEmpty())
        return;

    DisassemblerView* currdv = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());

    if(!currdv)
        return;

    if(!REDasm::Database::save(currdv->disassembler(), s.toStdString(), m_fileinfo.fileName().toStdString()))
        REDasm::log(REDasm::Database::lastError());
}

void MainWindow::onCloseClicked()
{
    this->closeFile();
    ui->action_Close->setEnabled(false);
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

void MainWindow::onImportSignatureClicked()
{
    QString s = QFileDialog::getOpenFileName(this, "Load Signature...", QString(), "REDasm Signature Database (*.sdb)");

    if(s.isEmpty())
        return;

    DisassemblerView* currdv = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());

    if(!currdv)
        return;

    REDasm::DisassemblerAPI* disassembler = currdv->disassembler();

    if(disassembler->loadSignature(s.toStdString()))
        return;

    QMessageBox msgbox(this);
    msgbox.setWindowTitle("Load Error");
    msgbox.setText(QString("Error loading \"%1\"").arg(QFileInfo(s).fileName()));
    msgbox.setStandardButtons(QMessageBox::Ok);
}

void MainWindow::onSettingsClicked()
{
    SettingsDialog sd(this);
    sd.exec();
}

void MainWindow::loadGeometry()
{
    REDasmSettings settings;

    if(settings.hasGeometry())
    {
        this->restoreGeometry(settings.geometry());
        return;
    }

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

        QAction* action = mnurecents->addAction(QString("%1 - %2").arg(i).arg(m_recents[i]));
        action->setData(m_recents[i]);
        connect(action, &QAction::triggered, this, &MainWindow::onRecentFileClicked);
    }
}

bool MainWindow::loadDatabase(const QString &filepath)
{
    std::string filename;
    REDasm::Disassembler* disassembler = REDasm::Database::load(filepath.toStdString(), filename);

    if(!disassembler)
    {
        if(m_fileinfo.suffix() == RDB_SIGNATURE_EXT)
            REDasm::log(REDasm::Database::lastError());

        return false;
    }

    m_fileinfo = QFileInfo(QString::fromStdString(filename));
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
    this->loadRecents();

    if(this->loadDatabase(filepath))
        return;

    REDasm::Buffer buffer = REDasm::Buffer::fromFile(filepath.toStdString());

    if(!buffer.empty())
        this->initDisassembler(buffer);
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

bool MainWindow::checkPlugins(REDasm::Buffer& buffer, REDasm::FormatPlugin** format, REDasm::AssemblerPlugin** assembler)
{
    *format = REDasm::getFormat(buffer);

    if((*format)->isBinary()) // Use manual loader
    {
        ManualLoadDialog dlgmanload(*format, this);

        if(dlgmanload.exec() != ManualLoadDialog::Accepted)
            return false;
    }

    *assembler = REDasm::getAssembler((*format)->assembler());

    if(!(*assembler))
    {
        QMessageBox::information(this, "Assembler not found", QString("Cannot find assembler '%1'").arg(QString::fromStdString((*format)->assembler())));
        return false;
    }

    return true;
}

void MainWindow::showDisassemblerView(REDasm::Disassembler *disassembler)
{
    disassembler->busyChanged += [&]() {
        QMetaObject::invokeMethod(this, "checkCommandState", Qt::QueuedConnection);
    };

    ui->pteOutput->clear();

    QWidget* oldwidget = ui->stackView->widget(0);

    if(oldwidget)
    {
        ui->stackView->removeWidget(oldwidget);
        oldwidget->deleteLater();
    }

    DisassemblerView *dv = new DisassemblerView(m_pbstatus, ui->leFilter, ui->stackView);
    dv->setDisassembler(disassembler);
    ui->stackView->addWidget(dv);

    this->setViewWidgetsVisible(true);
    this->checkCommandState();
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

    REDasmSettings settings;
    settings.changeGeometry(this->saveGeometry());
    return true;
}

void MainWindow::closeFile()
{
    // TODO: messageBox for confirmation?

    if(m_disassembler != NULL)
    {
        m_disassembler->busyChanged.disconnect();
        m_disassembler->stop();
        m_disassembler = NULL;
    }

    QWidget* oldwidget = ui->stackView->widget(0);

    if(oldwidget != NULL)
    {
        ui->stackView->removeWidget(oldwidget);
        oldwidget->deleteLater();
    }

    ui->pteOutput->clear();
    m_lblstatus->clear();
    m_lblprogress->setVisible(false);
    m_pbstatus->setVisible(false);
    this->setViewWidgetsVisible(false);
}

void MainWindow::initDisassembler(REDasm::Buffer& buffer)
{
    REDasm::FormatPlugin* format = NULL;
    REDasm::AssemblerPlugin* assembler = NULL;

    if(!this->checkPlugins(buffer, &format, &assembler))
        return;

    m_disassembler = new REDasm::Disassembler(assembler, format);

    m_disassembler->busyChanged += [&]() {
        DisassemblerView* currdv = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());

        if(currdv)
            QMetaObject::invokeMethod(m_lblprogress, "setVisible", Qt::QueuedConnection, Q_ARG(bool, currdv->disassembler()->busy()));
    };

    this->showDisassemblerView(m_disassembler); // Take ownership
    m_disassembler->disassemble();
}

void MainWindow::setViewWidgetsVisible(bool b)
{
    ui->dockSymbols->setVisible(b);
    ui->dockReferences->setVisible(b);
    ui->dockListingMap->setVisible(b);
}

void MainWindow::onAboutClicked()
{
    AboutDialog dlgabout(this);
    dlgabout.exec();
}

void MainWindow::checkCommandState()
{
    DisassemblerView* currdv = dynamic_cast<DisassemblerView*>(ui->stackView->currentWidget());

    if(!currdv)
        return;

    REDasm::DisassemblerAPI* disassembler = currdv->disassembler();

    this->setWindowTitle(disassembler->busy() ? QString("%1 (Working)").arg(m_fileinfo.fileName()) :
                                                m_fileinfo.fileName());

    ui->action_Save->setEnabled(!disassembler->busy());
    ui->action_Save_As->setEnabled(!disassembler->busy());
    ui->action_Import_Signature->setEnabled(!disassembler->busy());
    ui->action_Close->setEnabled(true);
}
