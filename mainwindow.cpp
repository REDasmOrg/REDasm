#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "widgets/disassemblerview/disassemblerview.h"
#include <QDragEnterEvent>
#include <QDesktopWidget>
#include <QMimeDatabase>
#include <QMessageBox>
#include <QMimeData>
#include <QFileDialog>
#include <QFile>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    REDasm::init();

    ui->setupUi(this);

    this->_lblstatus = new QLabel(this);
    ui->statusBar->addPermanentWidget(this->_lblstatus, 1);

    this->centerWindow();
    this->setAcceptDrops(true);
}

MainWindow::~MainWindow()
{
    delete ui;
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

void MainWindow::on_tbOpen_clicked()
{
    QString s = QFileDialog::getOpenFileName(this, "Disassemble file...");

    if(s.isEmpty())
        return;

    this->load(s);
}

void MainWindow::centerWindow()
{
    QRect position = this->frameGeometry();
    position.moveCenter(QDesktopWidget().availableGeometry().center());
    this->move(position.topLeft());
}

void MainWindow::load(const QString& s)
{
    QFile f(s);

    if(!f.open(QFile::ReadOnly))
        return;

    QFileInfo fi(s);
    this->setWindowTitle(fi.fileName());

    this->_loadeddata = f.readAll();
    f.close();

    if(!this->_loadeddata.isEmpty())
        this->analyze();
}

void MainWindow::analyze()
{
    REDasm::FormatPlugin* format = REDasm::getFormat(reinterpret_cast<u8*>(this->_loadeddata.data()));

    if(!format)
    {
        QMessageBox::information(this, "Info", "Unsupported Format");
        return;
    }

    REDasm::ProcessorPlugin* processor = REDasm::getProcessor(format->processor());

    if(!processor)
    {
        if(!format->processor())
            QMessageBox::information(this, "Processor not found", "Unsupported processor");
        else
            QMessageBox::information(this, "Processor not found", QString("Cannot find processor '%1'").arg(QString::fromUtf8(format->processor())));

        return;
    }

    this->display(processor, format);
}

void MainWindow::display(REDasm::ProcessorPlugin* processor, REDasm::FormatPlugin* format)
{
    REDasm::Buffer buffer(this->_loadeddata.data(), this->_loadeddata.length());
    DisassemblerView *olddv = NULL, *dv = new DisassemblerView(this->_lblstatus, ui->stackView);
    REDasm::Disassembler* disassembler = new REDasm::Disassembler(buffer, processor, format);

    disassembler->statusCallback([this](std::string s) {
        QMetaObject::invokeMethod(this->_lblstatus, "setText", Qt::QueuedConnection, Q_ARG(QString, S_TO_QS(s)));
    });

    dv->setDisassembler(disassembler);
    ui->stackView->addWidget(dv);

    QWidget* oldwidget = static_cast<DisassemblerView*>(ui->stackView->widget(0));

    if((olddv = dynamic_cast<DisassemblerView*>(oldwidget)) && olddv->busy())
    {
        connect(olddv, &DisassemblerView::done, [this]() {
            QObject* sender = this->sender();
            ui->stackView->removeWidget(static_cast<QWidget*>(sender));
            sender->deleteLater();
        });

        return;
    }

    ui->stackView->removeWidget(oldwidget);
    oldwidget->deleteLater();
}

void MainWindow::on_tbAbout_clicked()
{
    QMessageBox::information(this, "About REDasm", "REDasm Disassembler\nVersion 1.0\nBy Dax");
}
