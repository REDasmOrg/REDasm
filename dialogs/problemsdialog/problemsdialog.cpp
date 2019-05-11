#include "problemsdialog.h"
#include "ui_problemsdialog.h"
#include <QStandardItemModel>
#include <redasm/redasm.h>

ProblemsDialog::ProblemsDialog(QWidget *parent) : QDialog(parent), ui(new Ui::ProblemsDialog)
{
    ui->setupUi(this);

    QStandardItemModel* m = new QStandardItemModel(ui->lvProblems);

    for(const std::string& problem : REDasm::Context::problems())
        m->appendRow(new QStandardItem(QString::fromStdString(problem)));

    ui->lvProblems->setModel(m);
}

ProblemsDialog::~ProblemsDialog()
{
    delete ui;
}
