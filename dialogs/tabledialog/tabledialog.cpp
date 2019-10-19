#include "tabledialog.h"
#include "ui_tabledialog.h"

TableDialog::TableDialog(QWidget *parent) : QDialog(parent), ui(new Ui::TableDialog)
{
    ui->setupUi(this);
    ui->tbvTable->setCornerButtonEnabled(true);

    ui->tbvTable->setStyleSheet(QString("QTableCornerButton::section { border-width: 1px; border-color: %1; border-style:solid; }")
                                .arg(qApp->palette().color(QPalette::Shadow).name()));

    ui->tbvTable->verticalHeader()->setDefaultSectionSize(ui->tbvTable->verticalHeader()->minimumSectionSize());
    ui->tbvTable->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
}

TableDialog::~TableDialog() { delete ui; }
void TableDialog::setButtonBoxVisible(bool b) { ui->buttonBox->setVisible(b); }

void TableDialog::setModel(QAbstractItemModel* model)
{
    if(!model->parent()) model->setParent(this);
    ui->tbvTable->setModel(model);

    for(int i = 0; i < model->columnCount(); i++)
        ui->tbvTable->horizontalHeader()->setSectionResizeMode(i, QHeaderView::Stretch);
}
