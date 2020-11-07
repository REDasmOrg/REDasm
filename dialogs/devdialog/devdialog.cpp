#include "devdialog.h"
#include "ui_devdialog.h"
#include "../renderer/surfaceqt.h"

DevDialog::DevDialog(QWidget *parent) : QDialog(parent), ui(new Ui::DevDialog)
{
    ui->setupUi(this);
    ui->tabWidget->setStyleSheet("QTabWidget::pane { border: 0; }");
}

void DevDialog::setCommand(ICommand* command)
{
    m_command = command;

    if(m_command)
        disconnect(m_command->surface(), &SurfaceQt::positionChanged, this, nullptr);

    connect(m_command->surface(), &SurfaceQt::positionChanged, this, [&]() {
        ui->tabDocument->updateInformation();
        ui->tabRDIL->updateInformation();
    });

    ui->tabDocument->setCommand(command);
    ui->tabBlocks->setCommand(command);
    ui->tabGraphs->setCommand(command);
    ui->tabRDIL->setCommand(command);
}

DevDialog::~DevDialog() { delete ui; }
