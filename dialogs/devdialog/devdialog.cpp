#include "devdialog.h"
#include "ui_devdialog.h"

DevDialog::DevDialog(QWidget *parent) : QDialog(parent), ui(new Ui::DevDialog)
{
    ui->setupUi(this);
    ui->tabWidget->setStyleSheet("QTabWidget::pane { border: 0; }");

    RDEvent_Subscribe(this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<DevDialog*>(e->owner);
        if(!thethis->m_command || !thethis->isVisible()) return;
        if(e->eventid != Event_CursorPositionChanged) return;
        if(e->sender != thethis->m_command->cursor()) return;

        QMetaObject::invokeMethod(thethis->ui->tabRDIL, "updateInformation", Qt::QueuedConnection);
        QMetaObject::invokeMethod(thethis->ui->tabDocument, "updateInformation", Qt::QueuedConnection);
    }, nullptr);
}

void DevDialog::setCommand(IDisassemblerCommand* command)
{
    m_command = command;

    ui->tabDocument->setCommand(command);
    ui->tabBlocks->setCommand(command);
    ui->tabGraphs->setCommand(command);
    ui->tabRDIL->setCommand(command);
}

void DevDialog::dispose()
{
    RDEvent_Unsubscribe(this);
    this->deleteLater();
}

DevDialog::~DevDialog() { delete ui; }
