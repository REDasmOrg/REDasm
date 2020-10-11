#include "problemsdialog.h"
#include "ui_problemsdialog.h"
#include <QStandardItemModel>
#include <rdapi/rdapi.h>

ProblemsDialog::ProblemsDialog(const RDContextPtr& ctx, QWidget *parent) : QDialog(parent), ui(new Ui::ProblemsDialog), m_context(ctx)
{
    ui->setupUi(this);
    m_problemsmodel = new QStandardItemModel(ui->lvProblems);

    RDContext_GetProblems(ctx.get(), [](const char* s, void* userdata) {
        ProblemsDialog* thethis = reinterpret_cast<ProblemsDialog*>(userdata);
        thethis->m_problemsmodel->appendRow(new QStandardItem(s));
    }, this);

    ui->lvProblems->setModel(m_problemsmodel);
}

ProblemsDialog::~ProblemsDialog() { delete ui; }
