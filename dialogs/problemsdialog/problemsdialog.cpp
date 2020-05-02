#include "problemsdialog.h"
#include "ui_problemsdialog.h"
#include <QStandardItemModel>
#include <rdapi/rdapi.h>

ProblemsDialog::ProblemsDialog(QWidget *parent) : QDialog(parent), ui(new Ui::ProblemsDialog)
{
    ui->setupUi(this);
    m_problemsmodel = new QStandardItemModel(ui->lvProblems);

    RD_GetProblems([](const char* s, void* userdata) {
        ProblemsDialog* thethis = reinterpret_cast<ProblemsDialog*>(userdata);
        thethis->m_problemsmodel->appendRow(new QStandardItem(s));
    }, this);

    ui->lvProblems->setModel(m_problemsmodel);
}

ProblemsDialog::~ProblemsDialog() { delete ui; }
