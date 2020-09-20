#include "devdialog.h"
#include "ui_devdialog.h"

DevDialog::DevDialog(QWidget *parent) : QDialog(parent), ui(new Ui::DevDialog)
{
    ui->setupUi(this);
    ui->tabWidget->setStyleSheet("QTabWidget::pane { border: 0; }");
}

void DevDialog::setCommand(IDisassemblerCommand* command)
{
    m_command = command;

    RDDisassembler_Subscribe(command->disassembler().get(), this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<DevDialog*>(e->owner);
        if(!thethis->m_command || !thethis->isVisible()) return;
        if(e->eventid != Event_CursorPositionChanged) return;
        if(e->sender != thethis->m_command->cursor()) return;

        QMetaObject::invokeMethod(thethis->ui->tabRDIL, "updateInformation", Qt::QueuedConnection);
        QMetaObject::invokeMethod(thethis->ui->tabDocument, "updateInformation", Qt::QueuedConnection);
    }, nullptr);

    ui->tabDocument->setCommand(command);
    ui->tabBlocks->setCommand(command);
    ui->tabGraphs->setCommand(command);
    ui->tabRDIL->setCommand(command);
}

DevDialog::~DevDialog()
{
    if(m_command) RDDisassembler_Unsubscribe(m_command->disassembler().get(), this);
    delete ui;
}
