#include "devdialog.h"
#include "ui_devdialog.h"
#include "../models/dev/blocklistmodel.h"
#include "../models/dev/rdilmodel.h"

DevDialog::DevDialog(QWidget *parent) : QDialog(parent), ui(new Ui::DevDialog)
{
    ui->setupUi(this);
    ui->tabWidget->setStyleSheet("QTabWidget::pane { border: 0; }");

    RDEvent_Subscribe(this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<DevDialog*>(e->owner);
        if(!thethis->m_command || !thethis->isVisible()) return;
        if(e->eventid != Event_CursorPositionChanged) return;
        if(e->sender != thethis->m_command->cursor()) return;

        if(thethis->m_rdilmodel) thethis->m_rdilmodel->update();
        QMetaObject::invokeMethod(thethis->ui->tabDocument, "updateInformation", Qt::QueuedConnection);
    }, nullptr);
}

void DevDialog::setCommand(IDisassemblerCommand* command)
{
    m_command = command;

    m_blocklistmodel = new BlockListModel(command);
    m_rdilmodel = new RDILModel(command);

    ui->tabRDIL->setModel(m_rdilmodel);
    ui->tabBlocks->setModel(m_blocklistmodel);

    ui->tabDocument->setCommand(command);
    ui->tabGraphs->setCommand(command);
}

void DevDialog::dispose()
{
    RDEvent_Unsubscribe(this);
    this->deleteLater();
}

DevDialog::~DevDialog() { delete ui; }
