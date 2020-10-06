#include "problemsdialog.h"
#include "ui_problemsdialog.h"
#include <QStandardItemModel>
#include <rdapi/rdapi.h>

ProblemsDialog::ProblemsDialog(QWidget *parent) : QDialog(parent), ui(new Ui::ProblemsDialog)
{
    ui->setupUi(this);
    m_problemsmodel = new QStandardItemModel(ui->lvProblems);

    // FIXME: RDContext_GetProblems([](const char* s, void* userdata) {
    // FIXME:     ProblemsDialog* thethis = reinterpret_cast<ProblemsDialog*>(userdata);
    // FIXME:     thethis->m_problemsmodel->appendRow(new QStandardItem(s));
    // FIXME: }, this);

    ui->lvProblems->setModel(m_problemsmodel);
}

ProblemsDialog::~ProblemsDialog() { delete ui; }
