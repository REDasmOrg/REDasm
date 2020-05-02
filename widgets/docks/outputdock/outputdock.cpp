#include "outputdock.h"
#include "ui_outputdock.h"

OutputDock::OutputDock(QWidget *parent) : QDockWidget(parent), ui(new Ui::OutputDock)
{
    ui->setupUi(this);

    ui->leFilter->setVisible(false);
    ui->pteOutput->setReadOnly(true);
    ui->pteOutput->setUndoRedoEnabled(false);
    ui->pteOutput->setLineWrapMode(OutputWidget::NoWrap);
}

OutputDock::~OutputDock() { delete ui; }

void OutputDock::log(const QString& s)
{
    ui->pteOutput->insertPlainText(s + "\n");
    ui->pteOutput->ensureCursorVisible();
}

void OutputDock::clear() { ui->pteOutput->clear(); }
